# ObjectEzsignimportdocumentApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsignimportdocumentDownloadV1**](#ezsignimportdocumentdownloadv1) | **GET** /1/object/ezsignimportdocument/{pkiEzsignimportdocumentID}/download | Retrieve the content|

# **ezsignimportdocumentDownloadV1**
> EzsignimportdocumentDownloadV1Response ezsignimportdocumentDownloadV1()


### Example

```typescript
import {
    ObjectEzsignimportdocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignimportdocumentApi(configuration);

let pkiEzsignimportdocumentID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignimportdocumentDownloadV1(
    pkiEzsignimportdocumentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignimportdocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignimportdocumentDownloadV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

