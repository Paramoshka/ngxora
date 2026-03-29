package translator

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestTranslateHeaderFilter(t *testing.T) {
	hf := &gatewayv1.HTTPHeaderFilter{
		Set: []gatewayv1.HTTPHeader{
			{Name: "X-Set-1", Value: "value1"},
		},
		Add: []gatewayv1.HTTPHeader{
			{Name: "X-Add-1", Value: "value2"},
		},
		Remove: []string{"X-Remove-1"},
	}

	t.Run("request phase", func(t *testing.T) {
		cfgJSON, err := translateHeaderFilter(hf, "request")
		require.NoError(t, err)

		var parsed headersPluginConfig
		err = json.Unmarshal([]byte(cfgJSON), &parsed)
		require.NoError(t, err)

		assert.NotNil(t, parsed.Request)
		assert.Nil(t, parsed.Response)

		assert.Len(t, parsed.Request.Set, 1)
		assert.Equal(t, "X-Set-1", parsed.Request.Set[0].Name)
		assert.Equal(t, "value1", parsed.Request.Set[0].Value)

		assert.Len(t, parsed.Request.Add, 1)
		assert.Equal(t, "X-Add-1", parsed.Request.Add[0].Name)
		assert.Equal(t, "value2", parsed.Request.Add[0].Value)

		assert.Len(t, parsed.Request.Remove, 1)
		assert.Equal(t, "X-Remove-1", parsed.Request.Remove[0])
	})

	t.Run("response phase", func(t *testing.T) {
		cfgJSON, err := translateHeaderFilter(hf, "response")
		require.NoError(t, err)

		var parsed headersPluginConfig
		err = json.Unmarshal([]byte(cfgJSON), &parsed)
		require.NoError(t, err)

		assert.NotNil(t, parsed.Response)
		assert.Nil(t, parsed.Request)

		assert.Len(t, parsed.Response.Set, 1)
		assert.Equal(t, "X-Set-1", parsed.Response.Set[0].Name)
		assert.Equal(t, "value1", parsed.Response.Set[0].Value)

		assert.Len(t, parsed.Response.Add, 1)
		assert.Equal(t, "X-Add-1", parsed.Response.Add[0].Name)
		assert.Equal(t, "value2", parsed.Response.Add[0].Value)

		assert.Len(t, parsed.Response.Remove, 1)
		assert.Equal(t, "X-Remove-1", parsed.Response.Remove[0])
	})

	t.Run("invalid phase", func(t *testing.T) {
		_, err := translateHeaderFilter(hf, "invalid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported header filter phase")
	})
}
