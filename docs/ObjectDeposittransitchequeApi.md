# ObjectDeposittransitchequeApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**deposittransitchequeBatchDownloadV1**](#deposittransitchequebatchdownloadv1) | **POST** /1/object/deposittransitcheque/{pkiDeposittransitchequeID}/batchDownload | Download multiples attachments from a Deposittransitcheque|
|[**deposittransitchequeGetAttachmentsV1**](#deposittransitchequegetattachmentsv1) | **GET** /1/object/deposittransitcheque/{pkiDeposittransitchequeID}/getAttachments | Retrieve Deposittransitcheque\&#39;s attachments|
|[**deposittransitchequeImportIntoEDMV1**](#deposittransitchequeimportintoedmv1) | **POST** /1/object/deposittransitcheque/{pkiDeposittransitchequeID}/importIntoEDM | Import attachments into the Deposittransitcheque|

# **deposittransitchequeBatchDownloadV1**
> File deposittransitchequeBatchDownloadV1(deposittransitchequeBatchDownloadV1Request)


### Example

```typescript
import {
    ObjectDeposittransitchequeApi,
    Configuration,
    DeposittransitchequeBatchDownloadV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDeposittransitchequeApi(configuration);

let pkiDeposittransitchequeID: number; // (default to undefined)
let deposittransitchequeBatchDownloadV1Request: DeposittransitchequeBatchDownloadV1Request; //

const { status, data } = await apiInstance.deposittransitchequeBatchDownloadV1(
    pkiDeposittransitchequeID,
    deposittransitchequeBatchDownloadV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **deposittransitchequeBatchDownloadV1Request** | **DeposittransitchequeBatchDownloadV1Request**|  | |
| **pkiDeposittransitchequeID** | [**number**] |  | defaults to undefined|


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

# **deposittransitchequeGetAttachmentsV1**
> DeposittransitchequeGetAttachmentsV1Response deposittransitchequeGetAttachmentsV1()


### Example

```typescript
import {
    ObjectDeposittransitchequeApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDeposittransitchequeApi(configuration);

let pkiDeposittransitchequeID: number; // (default to undefined)

const { status, data } = await apiInstance.deposittransitchequeGetAttachmentsV1(
    pkiDeposittransitchequeID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDeposittransitchequeID** | [**number**] |  | defaults to undefined|


### Return type

**DeposittransitchequeGetAttachmentsV1Response**

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

# **deposittransitchequeImportIntoEDMV1**
> DeposittransitchequeImportIntoEDMV1Response deposittransitchequeImportIntoEDMV1(deposittransitchequeImportIntoEDMV1Request)


### Example

```typescript
import {
    ObjectDeposittransitchequeApi,
    Configuration,
    DeposittransitchequeImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDeposittransitchequeApi(configuration);

let pkiDeposittransitchequeID: number; // (default to undefined)
let deposittransitchequeImportIntoEDMV1Request: DeposittransitchequeImportIntoEDMV1Request; //

const { status, data } = await apiInstance.deposittransitchequeImportIntoEDMV1(
    pkiDeposittransitchequeID,
    deposittransitchequeImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **deposittransitchequeImportIntoEDMV1Request** | **DeposittransitchequeImportIntoEDMV1Request**|  | |
| **pkiDeposittransitchequeID** | [**number**] |  | defaults to undefined|


### Return type

**DeposittransitchequeImportIntoEDMV1Response**

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

