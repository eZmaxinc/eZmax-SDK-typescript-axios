# ObjectAdjustmentApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**adjustmentBatchDownloadV1**](#adjustmentbatchdownloadv1) | **POST** /1/object/adjustment/{pkiAdjustmentID}/batchDownload | Download multiples attachments from an Adjustment|
|[**adjustmentGetAttachmentsV1**](#adjustmentgetattachmentsv1) | **GET** /1/object/adjustment/{pkiAdjustmentID}/getAttachments | Retrieve Adjustment\&#39;s attachments|
|[**adjustmentGetCommunicationCountV1**](#adjustmentgetcommunicationcountv1) | **GET** /1/object/adjustment/{pkiAdjustmentID}/getCommunicationCount | Retrieve Communication count|
|[**adjustmentGetCommunicationListV1**](#adjustmentgetcommunicationlistv1) | **GET** /1/object/adjustment/{pkiAdjustmentID}/getCommunicationList | Retrieve Communication list|
|[**adjustmentGetCommunicationrecipientsV1**](#adjustmentgetcommunicationrecipientsv1) | **GET** /1/object/adjustment/{pkiAdjustmentID}/getCommunicationrecipients | Retrieve Communication recipients|
|[**adjustmentGetCommunicationsendersV1**](#adjustmentgetcommunicationsendersv1) | **GET** /1/object/adjustment/{pkiAdjustmentID}/getCommunicationsenders | Retrieve Communication senders|
|[**adjustmentImportIntoEDMV1**](#adjustmentimportintoedmv1) | **POST** /1/object/adjustment/{pkiAdjustmentID}/importIntoEDM | Import attachments into the Adjustment|

# **adjustmentBatchDownloadV1**
> File adjustmentBatchDownloadV1(adjustmentBatchDownloadV1Request)


### Example

```typescript
import {
    ObjectAdjustmentApi,
    Configuration,
    AdjustmentBatchDownloadV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectAdjustmentApi(configuration);

let pkiAdjustmentID: number; // (default to undefined)
let adjustmentBatchDownloadV1Request: AdjustmentBatchDownloadV1Request; //

const { status, data } = await apiInstance.adjustmentBatchDownloadV1(
    pkiAdjustmentID,
    adjustmentBatchDownloadV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **adjustmentBatchDownloadV1Request** | **AdjustmentBatchDownloadV1Request**|  | |
| **pkiAdjustmentID** | [**number**] |  | defaults to undefined|


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

# **adjustmentGetAttachmentsV1**
> AdjustmentGetAttachmentsV1Response adjustmentGetAttachmentsV1()


### Example

```typescript
import {
    ObjectAdjustmentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectAdjustmentApi(configuration);

let pkiAdjustmentID: number; // (default to undefined)

const { status, data } = await apiInstance.adjustmentGetAttachmentsV1(
    pkiAdjustmentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiAdjustmentID** | [**number**] |  | defaults to undefined|


### Return type

**AdjustmentGetAttachmentsV1Response**

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
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **adjustmentGetCommunicationCountV1**
> AdjustmentGetCommunicationCountV1Response adjustmentGetCommunicationCountV1()


### Example

```typescript
import {
    ObjectAdjustmentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectAdjustmentApi(configuration);

let pkiAdjustmentID: number; // (default to undefined)

const { status, data } = await apiInstance.adjustmentGetCommunicationCountV1(
    pkiAdjustmentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiAdjustmentID** | [**number**] |  | defaults to undefined|


### Return type

**AdjustmentGetCommunicationCountV1Response**

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
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **adjustmentGetCommunicationListV1**
> AdjustmentGetCommunicationListV1Response adjustmentGetCommunicationListV1()


### Example

```typescript
import {
    ObjectAdjustmentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectAdjustmentApi(configuration);

let pkiAdjustmentID: number; // (default to undefined)

const { status, data } = await apiInstance.adjustmentGetCommunicationListV1(
    pkiAdjustmentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiAdjustmentID** | [**number**] |  | defaults to undefined|


### Return type

**AdjustmentGetCommunicationListV1Response**

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
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **adjustmentGetCommunicationrecipientsV1**
> AdjustmentGetCommunicationrecipientsV1Response adjustmentGetCommunicationrecipientsV1()


### Example

```typescript
import {
    ObjectAdjustmentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectAdjustmentApi(configuration);

let pkiAdjustmentID: number; // (default to undefined)

const { status, data } = await apiInstance.adjustmentGetCommunicationrecipientsV1(
    pkiAdjustmentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiAdjustmentID** | [**number**] |  | defaults to undefined|


### Return type

**AdjustmentGetCommunicationrecipientsV1Response**

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
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **adjustmentGetCommunicationsendersV1**
> AdjustmentGetCommunicationsendersV1Response adjustmentGetCommunicationsendersV1()


### Example

```typescript
import {
    ObjectAdjustmentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectAdjustmentApi(configuration);

let pkiAdjustmentID: number; // (default to undefined)

const { status, data } = await apiInstance.adjustmentGetCommunicationsendersV1(
    pkiAdjustmentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiAdjustmentID** | [**number**] |  | defaults to undefined|


### Return type

**AdjustmentGetCommunicationsendersV1Response**

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
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **adjustmentImportIntoEDMV1**
> AdjustmentImportIntoEDMV1Response adjustmentImportIntoEDMV1(adjustmentImportIntoEDMV1Request)


### Example

```typescript
import {
    ObjectAdjustmentApi,
    Configuration,
    AdjustmentImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectAdjustmentApi(configuration);

let pkiAdjustmentID: number; // (default to undefined)
let adjustmentImportIntoEDMV1Request: AdjustmentImportIntoEDMV1Request; //

const { status, data } = await apiInstance.adjustmentImportIntoEDMV1(
    pkiAdjustmentID,
    adjustmentImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **adjustmentImportIntoEDMV1Request** | **AdjustmentImportIntoEDMV1Request**|  | |
| **pkiAdjustmentID** | [**number**] |  | defaults to undefined|


### Return type

**AdjustmentImportIntoEDMV1Response**

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

