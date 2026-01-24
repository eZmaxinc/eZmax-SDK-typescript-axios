# ObjectAttachmentApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**attachmentDownloadV1**](#attachmentdownloadv1) | **GET** /1/object/attachment/{pkiAttachmentID}/download | Retrieve the content|
|[**attachmentGetAttachmentlogsV1**](#attachmentgetattachmentlogsv1) | **GET** /1/object/attachment/{pkiAttachmentID}/getAttachmentlogs | Retrieve the Attachmentlogs|

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
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

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
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

