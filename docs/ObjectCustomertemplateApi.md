# ObjectCustomertemplateApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**customertemplateGetDocumenttypechecklistV1**](#customertemplategetdocumenttypechecklistv1) | **GET** /1/object/customertemplate/{pkiCustomertemplateID}/getDocumenttypechecklist | Retrieve Document type checklist|
|[**customertemplateSyncDocumenttypechecklistV1**](#customertemplatesyncdocumenttypechecklistv1) | **POST** /1/object/customertemplate/{pkiCustomertemplateID}/syncDocumenttypechecklist | Synchronize Document type checklist|

# **customertemplateGetDocumenttypechecklistV1**
> CustomertemplateGetDocumenttypechecklistV1Response customertemplateGetDocumenttypechecklistV1()


### Example

```typescript
import {
    ObjectCustomertemplateApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCustomertemplateApi(configuration);

let pkiCustomertemplateID: number; // (default to undefined)

const { status, data } = await apiInstance.customertemplateGetDocumenttypechecklistV1(
    pkiCustomertemplateID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiCustomertemplateID** | [**number**] |  | defaults to undefined|


### Return type

**CustomertemplateGetDocumenttypechecklistV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **customertemplateSyncDocumenttypechecklistV1**
> CustomertemplateSyncDocumenttypechecklistV1Response customertemplateSyncDocumenttypechecklistV1()


### Example

```typescript
import {
    ObjectCustomertemplateApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCustomertemplateApi(configuration);

let pkiCustomertemplateID: number; // (default to undefined)
let body: object; // (optional)

const { status, data } = await apiInstance.customertemplateSyncDocumenttypechecklistV1(
    pkiCustomertemplateID,
    body
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **body** | **object**|  | |
| **pkiCustomertemplateID** | [**number**] |  | defaults to undefined|


### Return type

**CustomertemplateSyncDocumenttypechecklistV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

