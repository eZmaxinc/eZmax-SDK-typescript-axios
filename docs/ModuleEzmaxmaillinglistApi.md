# ModuleEzmaxmaillinglistApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezmaxmaillinglistSubscribeV1**](#ezmaxmaillinglistsubscribev1) | **POST** /1/module/ezmaxmaillinglist/subscribe | Subscribe to specific Ezmaxmaillinglist|

# **ezmaxmaillinglistSubscribeV1**
> EzmaxmaillinglistSubscribeV1Response ezmaxmaillinglistSubscribeV1(ezmaxmaillinglistSubscribeV1Request)

Users can subscribe to specific Ezmaxmaillinglist

### Example

```typescript
import {
    ModuleEzmaxmaillinglistApi,
    Configuration,
    EzmaxmaillinglistSubscribeV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ModuleEzmaxmaillinglistApi(configuration);

let ezmaxmaillinglistSubscribeV1Request: EzmaxmaillinglistSubscribeV1Request; //

const { status, data } = await apiInstance.ezmaxmaillinglistSubscribeV1(
    ezmaxmaillinglistSubscribeV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezmaxmaillinglistSubscribeV1Request** | **EzmaxmaillinglistSubscribeV1Request**|  | |


### Return type

**EzmaxmaillinglistSubscribeV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

