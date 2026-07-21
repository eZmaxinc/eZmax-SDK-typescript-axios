# ExternalEzmaxpartnerApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezmaxpartnerSubscribeV1**](#ezmaxpartnersubscribev1) | **POST** /1/external/ezmaxpartner/subscribe | Subscribe to an Ezmaxparnerproductstage|

# **ezmaxpartnerSubscribeV1**
> EzmaxpartnerSubscribeV1Response ezmaxpartnerSubscribeV1(ezmaxpartnerSubscribeV1Request)

Subscribe to an Ezmaxparnerproductstage

### Example

```typescript
import {
    ExternalEzmaxpartnerApi,
    Configuration,
    EzmaxpartnerSubscribeV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ExternalEzmaxpartnerApi(configuration);

let ezmaxpartnerSubscribeV1Request: EzmaxpartnerSubscribeV1Request; //

const { status, data } = await apiInstance.ezmaxpartnerSubscribeV1(
    ezmaxpartnerSubscribeV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezmaxpartnerSubscribeV1Request** | **EzmaxpartnerSubscribeV1Request**|  | |


### Return type

**EzmaxpartnerSubscribeV1Response**

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

