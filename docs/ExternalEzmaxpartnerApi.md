# ExternalEzmaxpartnerApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**externalpartnerSubscribeV1**](#externalpartnersubscribev1) | **POST** /1/external/ezmaxpartner/subscribe | Subscribe to an Ezmaxparnerproductstage|

# **externalpartnerSubscribeV1**
> DocumentationSubscribeV1Response externalpartnerSubscribeV1(documentationSubscribeV1Request)

Subscribe to an Ezmaxparnerproductstage

### Example

```typescript
import {
    ExternalEzmaxpartnerApi,
    Configuration,
    DocumentationSubscribeV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ExternalEzmaxpartnerApi(configuration);

let documentationSubscribeV1Request: DocumentationSubscribeV1Request; //

const { status, data } = await apiInstance.externalpartnerSubscribeV1(
    documentationSubscribeV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **documentationSubscribeV1Request** | **DocumentationSubscribeV1Request**|  | |


### Return type

**DocumentationSubscribeV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

