# ObjectAttachmentApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**attachmentDeleteV1**](#attachmentdeletev1) | **POST** /1/object/attachment/{pkiAttachmentID}/delete | Delete an existing attachment|
|[**attachmentDownloadV1**](#attachmentdownloadv1) | **GET** /1/object/attachment/{pkiAttachmentID}/download | Retrieve the content|
|[**attachmentGetAttachmentlogsV1**](#attachmentgetattachmentlogsv1) | **GET** /1/object/attachment/{pkiAttachmentID}/getAttachmentlogs | Retrieve the Attachmentlogs|
|[**attachmentRenameV1**](#attachmentrenamev1) | **POST** /1/object/attachment/{pkiAttachmentID}/rename | Rename an attachment|
|[**attachmentRestoreV1**](#attachmentrestorev1) | **POST** /1/object/attachment/{pkiAttachmentID}/restore | Restore a deleted attachment|
|[**attachmentSetDocumentTypeV1**](#attachmentsetdocumenttypev1) | **POST** /1/object/attachment/{pkiAttachmentID}/setDocumentType | Change attachment document type|
|[**attachmentSetPrivacyV1**](#attachmentsetprivacyv1) | **POST** /1/object/attachment/{pkiAttachmentID}/setPrivacy | Change the attachment privacy|
|[**attachmentValidateV1**](#attachmentvalidatev1) | **POST** /1/object/attachment/{pkiAttachmentID}/validate | Validate an existing attachment|

# **attachmentDeleteV1**
> AttachmentDeleteV1Response attachmentDeleteV1(body)

Te endpoint allows to delete an attachment.

### Example

```typescript
import {
    ObjectAttachmentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectAttachmentApi(configuration);

let pkiAttachmentID: number; // (default to undefined)
let body: object; //

const { status, data } = await apiInstance.attachmentDeleteV1(
    pkiAttachmentID,
    body
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **body** | **object**|  | |
| **pkiAttachmentID** | [**number**] |  | defaults to undefined|


### Return type

**AttachmentDeleteV1Response**

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
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

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

# **attachmentRestoreV1**
> AttachmentRestoreV1Response attachmentRestoreV1(attachmentRestoreV1Request)

The endpoints allows to restore a previously deleted attachment.

### Example

```typescript
import {
    ObjectAttachmentApi,
    Configuration,
    AttachmentRestoreV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectAttachmentApi(configuration);

let pkiAttachmentID: number; // (default to undefined)
let attachmentRestoreV1Request: AttachmentRestoreV1Request; //

const { status, data } = await apiInstance.attachmentRestoreV1(
    pkiAttachmentID,
    attachmentRestoreV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **attachmentRestoreV1Request** | **AttachmentRestoreV1Request**|  | |
| **pkiAttachmentID** | [**number**] |  | defaults to undefined|


### Return type

**AttachmentRestoreV1Response**

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

# **attachmentSetDocumentTypeV1**
> AttachmentSetDocumentTypeV1Response attachmentSetDocumentTypeV1(attachmentSetDocumentTypeV1Request)

The endpoint allows to change the checklist document type for an attachment.

### Example

```typescript
import {
    ObjectAttachmentApi,
    Configuration,
    AttachmentSetDocumentTypeV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectAttachmentApi(configuration);

let pkiAttachmentID: number; // (default to undefined)
let attachmentSetDocumentTypeV1Request: AttachmentSetDocumentTypeV1Request; //

const { status, data } = await apiInstance.attachmentSetDocumentTypeV1(
    pkiAttachmentID,
    attachmentSetDocumentTypeV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **attachmentSetDocumentTypeV1Request** | **AttachmentSetDocumentTypeV1Request**|  | |
| **pkiAttachmentID** | [**number**] |  | defaults to undefined|


### Return type

**AttachmentSetDocumentTypeV1Response**

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
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **attachmentSetPrivacyV1**
> AttachmentSetPrivacyV1Response attachmentSetPrivacyV1(attachmentSetPrivacyV1Request)

The endpoint allows to change an attachment\'s access privacy.

### Example

```typescript
import {
    ObjectAttachmentApi,
    Configuration,
    AttachmentSetPrivacyV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectAttachmentApi(configuration);

let pkiAttachmentID: number; // (default to undefined)
let attachmentSetPrivacyV1Request: AttachmentSetPrivacyV1Request; //

const { status, data } = await apiInstance.attachmentSetPrivacyV1(
    pkiAttachmentID,
    attachmentSetPrivacyV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **attachmentSetPrivacyV1Request** | **AttachmentSetPrivacyV1Request**|  | |
| **pkiAttachmentID** | [**number**] |  | defaults to undefined|


### Return type

**AttachmentSetPrivacyV1Response**

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
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **attachmentValidateV1**
> AttachmentValidateV1Response attachmentValidateV1(attachmentValidateV1Request)

This endpoint allows to validate or reject an attachment.

### Example

```typescript
import {
    ObjectAttachmentApi,
    Configuration,
    AttachmentValidateV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectAttachmentApi(configuration);

let pkiAttachmentID: number; // (default to undefined)
let attachmentValidateV1Request: AttachmentValidateV1Request; //

const { status, data } = await apiInstance.attachmentValidateV1(
    pkiAttachmentID,
    attachmentValidateV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **attachmentValidateV1Request** | **AttachmentValidateV1Request**|  | |
| **pkiAttachmentID** | [**number**] |  | defaults to undefined|


### Return type

**AttachmentValidateV1Response**

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
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

