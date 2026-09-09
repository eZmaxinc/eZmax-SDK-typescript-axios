# ObjectDisclosureApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**disclosureBatchDownloadV1**](#disclosurebatchdownloadv1) | **POST** /1/object/disclosure/{pkiDisclosureID}/batchDownload | Download multiples attachments from a Disclosure|
|[**disclosureGetAttachmentsV1**](#disclosuregetattachmentsv1) | **GET** /1/object/disclosure/{pkiDisclosureID}/getAttachments | Retrieve Disclosure\&#39;s attachments|
|[**disclosureImportIntoEDMV1**](#disclosureimportintoedmv1) | **POST** /1/object/disclosure/{pkiDisclosureID}/importIntoEDM | Import attachments into the Disclosure|

# **disclosureBatchDownloadV1**
> File disclosureBatchDownloadV1(disclosureBatchDownloadV1Request)


### Example

```typescript
import {
    ObjectDisclosureApi,
    Configuration,
    DisclosureBatchDownloadV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDisclosureApi(configuration);

let pkiDisclosureID: number; // (default to undefined)
let disclosureBatchDownloadV1Request: DisclosureBatchDownloadV1Request; //

const { status, data } = await apiInstance.disclosureBatchDownloadV1(
    pkiDisclosureID,
    disclosureBatchDownloadV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **disclosureBatchDownloadV1Request** | **DisclosureBatchDownloadV1Request**|  | |
| **pkiDisclosureID** | [**number**] |  | defaults to undefined|


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

# **disclosureGetAttachmentsV1**
> DisclosureGetAttachmentsV1Response disclosureGetAttachmentsV1()


### Example

```typescript
import {
    ObjectDisclosureApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDisclosureApi(configuration);

let pkiDisclosureID: number; // (default to undefined)

const { status, data } = await apiInstance.disclosureGetAttachmentsV1(
    pkiDisclosureID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDisclosureID** | [**number**] |  | defaults to undefined|


### Return type

**DisclosureGetAttachmentsV1Response**

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

# **disclosureImportIntoEDMV1**
> DisclosureImportIntoEDMV1Response disclosureImportIntoEDMV1(disclosureImportIntoEDMV1Request)


### Example

```typescript
import {
    ObjectDisclosureApi,
    Configuration,
    DisclosureImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDisclosureApi(configuration);

let pkiDisclosureID: number; // (default to undefined)
let disclosureImportIntoEDMV1Request: DisclosureImportIntoEDMV1Request; //

const { status, data } = await apiInstance.disclosureImportIntoEDMV1(
    pkiDisclosureID,
    disclosureImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **disclosureImportIntoEDMV1Request** | **DisclosureImportIntoEDMV1Request**|  | |
| **pkiDisclosureID** | [**number**] |  | defaults to undefined|


### Return type

**DisclosureImportIntoEDMV1Response**

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

