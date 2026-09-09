# ObjectFolderApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**folderBatchDownloadV1**](#folderbatchdownloadv1) | **POST** /1/object/folder/{pkiFolderID}/batchDownload | Download multiples attachments from an Folder|
|[**folderGetAttachmentsV1**](#foldergetattachmentsv1) | **GET** /1/object/folder/{pkiFolderID}/getAttachments | Retrieve Folder\&#39;s attachments|
|[**folderImportIntoEDMV1**](#folderimportintoedmv1) | **POST** /1/object/folder/{pkiFolderID}/importIntoEDM | Import attachments into the Folder|

# **folderBatchDownloadV1**
> File folderBatchDownloadV1(folderBatchDownloadV1Request)


### Example

```typescript
import {
    ObjectFolderApi,
    Configuration,
    FolderBatchDownloadV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectFolderApi(configuration);

let pkiFolderID: number; // (default to undefined)
let folderBatchDownloadV1Request: FolderBatchDownloadV1Request; //

const { status, data } = await apiInstance.folderBatchDownloadV1(
    pkiFolderID,
    folderBatchDownloadV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **folderBatchDownloadV1Request** | **FolderBatchDownloadV1Request**|  | |
| **pkiFolderID** | [**number**] |  | defaults to undefined|


### Return type

**File**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/zip, text/xml, application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |
|**406** | The URL is valid, but one of the Accept header is not defined or invalid. For example, you set the header \&quot;Accept: application/json\&quot; but the function can only return \&quot;Content-type: image/png\&quot; |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **folderGetAttachmentsV1**
> FolderGetAttachmentsV1Response folderGetAttachmentsV1()


### Example

```typescript
import {
    ObjectFolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectFolderApi(configuration);

let pkiFolderID: number; // (default to undefined)

const { status, data } = await apiInstance.folderGetAttachmentsV1(
    pkiFolderID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiFolderID** | [**number**] |  | defaults to undefined|


### Return type

**FolderGetAttachmentsV1Response**

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

# **folderImportIntoEDMV1**
> FolderImportIntoEDMV1Response folderImportIntoEDMV1(folderImportIntoEDMV1Request)


### Example

```typescript
import {
    ObjectFolderApi,
    Configuration,
    FolderImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectFolderApi(configuration);

let pkiFolderID: number; // (default to undefined)
let folderImportIntoEDMV1Request: FolderImportIntoEDMV1Request; //

const { status, data } = await apiInstance.folderImportIntoEDMV1(
    pkiFolderID,
    folderImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **folderImportIntoEDMV1Request** | **FolderImportIntoEDMV1Request**|  | |
| **pkiFolderID** | [**number**] |  | defaults to undefined|


### Return type

**FolderImportIntoEDMV1Response**

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

