# ObjectExternalbrokerApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**externalbrokerImportIntoEDMV1**](#externalbrokerimportintoedmv1) | **POST** /1/object/externalbroker/{pkiExternalbrokerID}/importIntoEDM | Import attachments into the Externalbroker|

# **externalbrokerImportIntoEDMV1**
> ExternalbrokerImportIntoEDMV1Response externalbrokerImportIntoEDMV1(externalbrokerImportIntoEDMV1Request)



### Example

```typescript
import {
    ObjectExternalbrokerApi,
    Configuration,
    ExternalbrokerImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectExternalbrokerApi(configuration);

let pkiExternalbrokerID: number; // (default to undefined)
let externalbrokerImportIntoEDMV1Request: ExternalbrokerImportIntoEDMV1Request; //

const { status, data } = await apiInstance.externalbrokerImportIntoEDMV1(
    pkiExternalbrokerID,
    externalbrokerImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **externalbrokerImportIntoEDMV1Request** | **ExternalbrokerImportIntoEDMV1Request**|  | |
| **pkiExternalbrokerID** | [**number**] |  | defaults to undefined|


### Return type

**ExternalbrokerImportIntoEDMV1Response**

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

