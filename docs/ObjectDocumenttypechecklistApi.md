# ObjectDocumenttypechecklistApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**documenttypechecklistDeleteObjectV1**](#documenttypechecklistdeleteobjectv1) | **DELETE** /1/object/documenttypechecklist/{pkiDocumenttypechecklistID} | Delete an existing Documenttypechecklist|
|[**documenttypechecklistPatchObjectV1**](#documenttypechecklistpatchobjectv1) | **PATCH** /1/object/documenttypechecklist/{pkiDocumenttypechecklistID} | Patch an existing Documenttypechecklist|

# **documenttypechecklistDeleteObjectV1**
> DocumenttypechecklistDeleteObjectV1Response documenttypechecklistDeleteObjectV1()



### Example

```typescript
import {
    ObjectDocumenttypechecklistApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDocumenttypechecklistApi(configuration);

let pkiDocumenttypechecklistID: number; //The unique ID of the Documenttypechecklist (default to undefined)

const { status, data } = await apiInstance.documenttypechecklistDeleteObjectV1(
    pkiDocumenttypechecklistID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDocumenttypechecklistID** | [**number**] | The unique ID of the Documenttypechecklist | defaults to undefined|


### Return type

**DocumenttypechecklistDeleteObjectV1Response**

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

# **documenttypechecklistPatchObjectV1**
> DocumenttypechecklistPatchObjectV1Response documenttypechecklistPatchObjectV1(documenttypechecklistPatchObjectV1Request)



### Example

```typescript
import {
    ObjectDocumenttypechecklistApi,
    Configuration,
    DocumenttypechecklistPatchObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDocumenttypechecklistApi(configuration);

let pkiDocumenttypechecklistID: number; //The unique ID of the Documenttypechecklist (default to undefined)
let documenttypechecklistPatchObjectV1Request: DocumenttypechecklistPatchObjectV1Request; //

const { status, data } = await apiInstance.documenttypechecklistPatchObjectV1(
    pkiDocumenttypechecklistID,
    documenttypechecklistPatchObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **documenttypechecklistPatchObjectV1Request** | **DocumenttypechecklistPatchObjectV1Request**|  | |
| **pkiDocumenttypechecklistID** | [**number**] | The unique ID of the Documenttypechecklist | defaults to undefined|


### Return type

**DocumenttypechecklistPatchObjectV1Response**

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
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

