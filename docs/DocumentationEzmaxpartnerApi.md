# DocumentationEzmaxpartnerApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**documentationSubscribeV1**](#documentationsubscribev1) | **POST** /1/documentation/subscribe | Subscribe to an Ezmaxparnerproductstage|

# **documentationSubscribeV1**
> DocumentationSubscribeV1Response documentationSubscribeV1(documentationSubscribeV1Request)

Subscribe to an Ezmaxparnerproductstage

### Example

```typescript
import {
    DocumentationEzmaxpartnerApi,
    Configuration,
    DocumentationSubscribeV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new DocumentationEzmaxpartnerApi(configuration);

let documentationSubscribeV1Request: DocumentationSubscribeV1Request; //

const { status, data } = await apiInstance.documentationSubscribeV1(
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

