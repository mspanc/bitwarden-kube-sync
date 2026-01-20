package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"
	"time"

	sdk "github.com/bitwarden/sdk-go"
	"github.com/gofrs/uuid"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type Config struct {
	BitwardenAPIURL      string
	BitwardenIdentityURL string
	BitwardenAccessToken string
	BitwardenOrgID       string
	BitwardenProjectIDs  []string

	KubeSecretName  string
	KubeNamespace   string
	RefreshInterval time.Duration
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	cfg, err := loadConfigFromEnv()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	if cfg.KubeNamespace == "" {
		ns, err := detectNamespace()
		if err != nil {
			log.Fatalf("failed to determine namespace: %v", err)
		}
		cfg.KubeNamespace = ns
	}

	k8sClient, err := newInClusterClient()
	if err != nil {
		log.Fatalf("failed to create k8s client: %v", err)
	}

	log.Printf(
		"starting sync loop namespace=%s secret=%s projects=%d refresh=%s",
		cfg.KubeNamespace,
		cfg.KubeSecretName,
		len(cfg.BitwardenProjectIDs),
		cfg.RefreshInterval,
	)

	for {
		start := time.Now()

		if err := syncOnce(context.Background(), cfg, k8sClient); err != nil {
			log.Printf("ERROR sync failed: %v", err)
		}

		// Sleep only after the sync completes (no overlapping calls).
		sleep := cfg.RefreshInterval - time.Since(start)
		if sleep > 0 {
			time.Sleep(sleep)
		}
	}
}

func loadConfigFromEnv() (Config, error) {
	req := func(name string) (string, error) {
		v := strings.TrimSpace(os.Getenv(name))
		if v == "" {
			return "", fmt.Errorf("%s must be set", name)
		}
		return v, nil
	}

	apiURL, err := req("BITWARDEN_API_URL")
	if err != nil {
		return Config{}, err
	}
	identityURL, err := req("BITWARDEN_IDENTITY_URL")
	if err != nil {
		return Config{}, err
	}
	accessToken, err := req("BITWARDEN_ACCESS_TOKEN")
	if err != nil {
		return Config{}, err
	}
	orgID, err := req("BITWARDEN_ORGANIZATION_ID")
	if err != nil {
		return Config{}, err
	}
	projectIDsRaw, err := req("BITWARDEN_PROJECT_IDS")
	if err != nil {
		return Config{}, err
	}
	secretName, err := req("KUBE_SECRET_NAME")
	if err != nil {
		return Config{}, err
	}

	refresh := 60 * time.Second
	if v := strings.TrimSpace(os.Getenv("REFRESH_INTERVAL")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("REFRESH_INTERVAL invalid: %w", err)
		}
		if d <= 0 {
			return Config{}, fmt.Errorf("REFRESH_INTERVAL must be > 0")
		}
		refresh = d
	}

	projectIDs := splitCommaSeparated(projectIDsRaw)
	if len(projectIDs) == 0 {
		return Config{}, fmt.Errorf("BITWARDEN_PROJECT_IDS must contain at least one UUID")
	}

	if err := mustParseUUID("BITWARDEN_ORGANIZATION_ID", orgID); err != nil {
		return Config{}, err
	}
	for _, id := range projectIDs {
		if err := mustParseUUID("BITWARDEN_PROJECT_IDS item", id); err != nil {
			return Config{}, err
		}
	}

	return Config{
		BitwardenAPIURL:      apiURL,
		BitwardenIdentityURL: identityURL,
		BitwardenAccessToken: accessToken,
		BitwardenOrgID:       orgID,
		BitwardenProjectIDs:  projectIDs,

		KubeSecretName:  secretName,
		KubeNamespace:   strings.TrimSpace(os.Getenv("KUBE_NAMESPACE")), // optional
		RefreshInterval: refresh,
	}, nil
}

func mustParseUUID(name, value string) error {
	if _, err := uuid.FromString(value); err != nil {
		return fmt.Errorf("%s must be a valid UUID: %q", name, value)
	}
	return nil
}

func splitCommaSeparated(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func detectNamespace() (string, error) {
	// Highest priority: explicit override
	if ns := strings.TrimSpace(os.Getenv("KUBE_NAMESPACE")); ns != "" {
		return ns, nil
	}
	// Common downward API env var
	if ns := strings.TrimSpace(os.Getenv("POD_NAMESPACE")); ns != "" {
		return ns, nil
	}
	// Standard in-cluster namespace file
	b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err == nil {
		if ns := strings.TrimSpace(string(b)); ns != "" {
			return ns, nil
		}
	}
	return "", errors.New("namespace not found (set KUBE_NAMESPACE or POD_NAMESPACE)")
}

func newInClusterClient() (*kubernetes.Clientset, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(cfg)
}

func syncOnce(ctx context.Context, cfg Config, client *kubernetes.Clientset) error {
	log.Printf("sync start")

	data, err := fetchAndMergeSecrets(cfg)
	if err != nil {
		return err
	}

	if err := upsertSecret(ctx, client, cfg.KubeNamespace, cfg.KubeSecretName, data); err != nil {
		return err
	}

	log.Printf("sync ok keys=%d", len(data))
	return nil
}

func fetchAndMergeSecrets(cfg Config) (map[string][]byte, error) {
	bw, err := sdk.NewBitwardenClient(&cfg.BitwardenAPIURL, &cfg.BitwardenIdentityURL)
	if err != nil {
		return nil, fmt.Errorf("bitwarden init failed: %w", err)
	}
	defer bw.Close()

	if err := bw.AccessTokenLogin(cfg.BitwardenAccessToken, nil); err != nil {
		return nil, fmt.Errorf("bitwarden login failed: %w", err)
	}

	all, err := bw.Secrets().List(cfg.BitwardenOrgID)
	if err != nil {
		return nil, fmt.Errorf("bitwarden list secrets failed: %w", err)
	}

	byProject := map[string][]sdk.SecretResponse{}
	for _, s := range all.Data {
		// NOTE: adjust field names here if your sdk-go version differs.
		secret, err := bw.Secrets().Get(s.ID)
		if err != nil {
			return nil, fmt.Errorf("bitwarden get secret failed: %w", err)
		}
		var projectId = *secret.ProjectID

		if strings.TrimSpace(projectId) == "" {
			continue
		}
		byProject[projectId] = append(byProject[projectId], *secret)
	}

	merged := map[string][]byte{}

	for _, pid := range cfg.BitwardenProjectIDs {
		secrets := byProject[pid]
		if len(secrets) == 0 {
			log.Printf("WARN project has no secrets (or not accessible): projectId=%s", pid)
			continue
		}

		for _, s := range secrets {
			key := strings.TrimSpace(s.Key)
			if key == "" {
				continue
			}

			if _, exists := merged[key]; exists {
				log.Printf("WARN key %q overridden by later project %s", key, pid)
			}

			merged[key] = []byte(s.Value)
		}
	}

	return merged, nil
}

func upsertSecret(ctx context.Context, client *kubernetes.Clientset, namespace, name string, data map[string][]byte) error {
	secrets := client.CoreV1().Secrets(namespace)

	existing, err := secrets.Get(ctx, name, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("k8s get secret failed: %w", err)
	}

	if existing == nil || apierrors.IsNotFound(err) {
		_, err := secrets.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
			Type: corev1.SecretTypeOpaque,
			Data: data,
		}, metav1.CreateOptions{})
		if err == nil {
			log.Printf("k8s secret created: %s/%s", namespace, name)
		}
		return err
	}

	if equalBytesMap(existing.Data, data) {
		log.Printf("k8s secret up-to-date: %s/%s", namespace, name)
		return nil
	}

	existing.Type = corev1.SecretTypeOpaque
	existing.Data = data

	_, err = secrets.Update(ctx, existing, metav1.UpdateOptions{})
	if err == nil {
		log.Printf("k8s secret updated: %s/%s", namespace, name)
	}
	return err
}

func equalBytesMap(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok {
			return false
		}
		if !slices.Equal(av, bv) {
			return false
		}
	}
	return true
}
