# GlobalEzmaxclientApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**globalEzmaxclientVersionV1**](#globalezmaxclientversionv1) | **GET** /1/ezmaxclient/{pksEzmaxclientOs}/version | Retrieve the latest version of the Ezmaxclient|

# **globalEzmaxclientVersionV1**
> GlobalEzmaxclientVersionV1Response globalEzmaxclientVersionV1()

Retrieve the latest version of the Ezmaxclient that is available on the store.

### Example

```typescript
import {
    GlobalEzmaxclientApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new GlobalEzmaxclientApi(configuration);

let pksEzmaxclientOs: FieldPksEzmaxclientOs; // (default to undefined)

const { status, data } = await apiInstance.globalEzmaxclientVersionV1(
    pksEzmaxclientOs
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pksEzmaxclientOs** | **FieldPksEzmaxclientOs** |  | defaults to undefined|


### Return type

**GlobalEzmaxclientVersionV1Response**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

