package harness

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The entry shape is the one the harness logs when a browser wait with
// update-image-placeholder fills a REVIEW check's screenshot.
func TestGetLog_ReviewEntryCarriesThePageSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[
			{"src":"ExpectInvalidRequestUriErrorPage","result":"REVIEW","msg":"upload a screenshot","content_type":"text/html","matched_regexp":"Authorization error","page_source":"<h1 id=\"authorize-error\">Authorization error</h1>"},
			{"src":"ExpectRequestObjectWithLongStateErrorPage","result":"REVIEW","msg":"upload a screenshot","image_no_longer_required":true}
		]`))
	}))
	t.Cleanup(srv.Close)

	entries, err := (&Client{BaseURL: srv.URL, HTTPClient: srv.Client()}).GetLog(context.Background(), "t-1")
	require.NoError(t, err)
	require.Len(t, entries, 2)
	assert.Equal(t, ResultReview, entries[0].Result)
	assert.Equal(t, `<h1 id="authorize-error">Authorization error</h1>`, entries[0].PageSource)
	assert.Empty(t, entries[1].PageSource)
}
