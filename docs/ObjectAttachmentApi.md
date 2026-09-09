# ObjectAttachmentApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**attachmentDownloadV1**](#attachmentdownloadv1) | **GET** /1/object/attachment/{pkiAttachmentID}/download | Retrieve the content|
|[**attachmentGetAttachmentlogsV1**](#attachmentgetattachmentlogsv1) | **GET** /1/object/attachment/{pkiAttachmentID}/getAttachmentlogs | Retrieve the Attachmentlogs|
|[**attachmentRenameV1**](#attachmentrenamev1) | **POST** /1/object/attachment/{pkiAttachmentID}/rename | Rename an Attachment|

# **attachmentDownloadV1**
> attachmentDownloadV1()

Using this endpoint, you can retrieve the content of an attachment.

### Example

```typescript
import {
    ObjectAttachmentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectAttachmentApi(configuration);

let pkiAttachmentID: number; // (default to undefined)

const { status, data } = await apiInstance.attachmentDownloadV1(
    pkiAttachmentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiAttachmentID** | [**number**] |  | defaults to undefined|


### Return type

void (empty response body)

### Authorization

[Authorization](../README.md#Authorization), [Presigned](../README.md#Presigned)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**302** | The user has been redirected |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **attachmentGetAttachmentlogsV1**
> AttachmentGetAttachmentlogsV1Response attachmentGetAttachmentlogsV1()

Using this endpoint, you can retrieve the Attachmentlogs of an attachment.

### Example

```typescript
import {
    ObjectAttachmentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectAttachmentApi(configuration);

let pkiAttachmentID: number; // (default to undefined)

const { status, data } = await apiInstance.attachmentGetAttachmentlogsV1(
    pkiAttachmentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiAttachmentID** | [**number**] |  | defaults to undefined|


### Return type

**AttachmentGetAttachmentlogsV1Response**

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

# **attachmentRenameV1**
> AttachmentRenameV1Response attachmentRenameV1(attachmentRenameV1Request)

The endpoint allows to change the attachment\'s file name and category.

### Example

```typescript
import {
    ObjectAttachmentApi,
    Configuration,
    AttachmentRenameV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectAttachmentApi(configuration);

let pkiAttachmentID: number; // (default to undefined)
let attachmentRenameV1Request: AttachmentRenameV1Request; //

const { status, data } = await apiInstance.attachmentRenameV1(
    pkiAttachmentID,
    attachmentRenameV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **attachmentRenameV1Request** | **AttachmentRenameV1Request**|  | |
| **pkiAttachmentID** | [**number**] |  | defaults to undefined|


### Return type

**AttachmentRenameV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**403** | The request is not allowed to be executed. Look for detail about the error in the body. |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |
|**409** | The request failed due to a conflict with the resource state. Look for detail about the error in the body. |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

