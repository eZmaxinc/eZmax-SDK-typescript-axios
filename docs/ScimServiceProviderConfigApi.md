# ScimServiceProviderConfigApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**serviceProviderConfigGetObjectScimV2**](#serviceproviderconfiggetobjectscimv2) | **GET** /2/scim/ServiceProviderConfig | Get Service Provider Configuration|

# **serviceProviderConfigGetObjectScimV2**
> ScimServiceProviderConfig serviceProviderConfigGetObjectScimV2()


### Example

```typescript
import {
    ScimServiceProviderConfigApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ScimServiceProviderConfigApi(configuration);

const { status, data } = await apiInstance.serviceProviderConfigGetObjectScimV2();
```

### Parameters
This endpoint does not have any parameters.


### Return type

**ScimServiceProviderConfig**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | OK |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

