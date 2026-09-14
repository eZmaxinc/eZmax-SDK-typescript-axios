# ObjectDepositApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**depositBatchDownloadV1**](#depositbatchdownloadv1) | **POST** /1/object/deposit/{pkiDepositID}/batchDownload | Download multiples attachments from a Deposit|
|[**depositGetAttachmentsV1**](#depositgetattachmentsv1) | **GET** /1/object/deposit/{pkiDepositID}/getAttachments | Retrieve Deposit\&#39;s attachments|
|[**depositGetCommunicationCountV1**](#depositgetcommunicationcountv1) | **GET** /1/object/deposit/{pkiDepositID}/getCommunicationCount | Retrieve Communication count|
|[**depositGetCommunicationListV1**](#depositgetcommunicationlistv1) | **GET** /1/object/deposit/{pkiDepositID}/getCommunicationList | Retrieve Communication list|
|[**depositGetCommunicationrecipientsV1**](#depositgetcommunicationrecipientsv1) | **GET** /1/object/deposit/{pkiDepositID}/getCommunicationrecipients | Retrieve Communication recipients|
|[**depositGetCommunicationsendersV1**](#depositgetcommunicationsendersv1) | **GET** /1/object/deposit/{pkiDepositID}/getCommunicationsenders | Retrieve Communication senders|
|[**depositImportIntoEDMV1**](#depositimportintoedmv1) | **POST** /1/object/deposit/{pkiDepositID}/importIntoEDM | Import attachments into the Deposit|

# **depositBatchDownloadV1**
> File depositBatchDownloadV1(depositBatchDownloadV1Request)


### Example

```typescript
import {
    ObjectDepositApi,
    Configuration,
    DepositBatchDownloadV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDepositApi(configuration);

let pkiDepositID: number; // (default to undefined)
let depositBatchDownloadV1Request: DepositBatchDownloadV1Request; //

const { status, data } = await apiInstance.depositBatchDownloadV1(
    pkiDepositID,
    depositBatchDownloadV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **depositBatchDownloadV1Request** | **DepositBatchDownloadV1Request**|  | |
| **pkiDepositID** | [**number**] |  | defaults to undefined|


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

# **depositGetAttachmentsV1**
> DepositGetAttachmentsV1Response depositGetAttachmentsV1()


### Example

```typescript
import {
    ObjectDepositApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDepositApi(configuration);

let pkiDepositID: number; // (default to undefined)

const { status, data } = await apiInstance.depositGetAttachmentsV1(
    pkiDepositID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDepositID** | [**number**] |  | defaults to undefined|


### Return type

**DepositGetAttachmentsV1Response**

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

# **depositGetCommunicationCountV1**
> DepositGetCommunicationCountV1Response depositGetCommunicationCountV1()


### Example

```typescript
import {
    ObjectDepositApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDepositApi(configuration);

let pkiDepositID: number; // (default to undefined)

const { status, data } = await apiInstance.depositGetCommunicationCountV1(
    pkiDepositID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDepositID** | [**number**] |  | defaults to undefined|


### Return type

**DepositGetCommunicationCountV1Response**

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

# **depositGetCommunicationListV1**
> DepositGetCommunicationListV1Response depositGetCommunicationListV1()


### Example

```typescript
import {
    ObjectDepositApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDepositApi(configuration);

let pkiDepositID: number; // (default to undefined)

const { status, data } = await apiInstance.depositGetCommunicationListV1(
    pkiDepositID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDepositID** | [**number**] |  | defaults to undefined|


### Return type

**DepositGetCommunicationListV1Response**

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

# **depositGetCommunicationrecipientsV1**
> DepositGetCommunicationrecipientsV1Response depositGetCommunicationrecipientsV1()


### Example

```typescript
import {
    ObjectDepositApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDepositApi(configuration);

let pkiDepositID: number; // (default to undefined)

const { status, data } = await apiInstance.depositGetCommunicationrecipientsV1(
    pkiDepositID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDepositID** | [**number**] |  | defaults to undefined|


### Return type

**DepositGetCommunicationrecipientsV1Response**

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

# **depositGetCommunicationsendersV1**
> DepositGetCommunicationsendersV1Response depositGetCommunicationsendersV1()


### Example

```typescript
import {
    ObjectDepositApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDepositApi(configuration);

let pkiDepositID: number; // (default to undefined)

const { status, data } = await apiInstance.depositGetCommunicationsendersV1(
    pkiDepositID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDepositID** | [**number**] |  | defaults to undefined|


### Return type

**DepositGetCommunicationsendersV1Response**

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

# **depositImportIntoEDMV1**
> DepositImportIntoEDMV1Response depositImportIntoEDMV1(depositImportIntoEDMV1Request)


### Example

```typescript
import {
    ObjectDepositApi,
    Configuration,
    DepositImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDepositApi(configuration);

let pkiDepositID: number; // (default to undefined)
let depositImportIntoEDMV1Request: DepositImportIntoEDMV1Request; //

const { status, data } = await apiInstance.depositImportIntoEDMV1(
    pkiDepositID,
    depositImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **depositImportIntoEDMV1Request** | **DepositImportIntoEDMV1Request**|  | |
| **pkiDepositID** | [**number**] |  | defaults to undefined|


### Return type

**DepositImportIntoEDMV1Response**

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

