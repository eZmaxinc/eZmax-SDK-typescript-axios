# ObjectPaymentpreparationApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**paymentpreparationBatchDownloadV1**](#paymentpreparationbatchdownloadv1) | **POST** /1/object/paymentpreparation/{pkiPaymentpreparationID}/batchDownload | Download multiples attachments from an Paymentpreparation|
|[**paymentpreparationGetAttachmentsV1**](#paymentpreparationgetattachmentsv1) | **GET** /1/object/paymentpreparation/{pkiPaymentpreparationID}/getAttachments | Retrieve Paymentpreparation\&#39;s attachments|
|[**paymentpreparationImportIntoEDMV1**](#paymentpreparationimportintoedmv1) | **POST** /1/object/paymentpreparation/{pkiPaymentpreparationID}/importIntoEDM | Import attachments into the Paymentpreparation|

# **paymentpreparationBatchDownloadV1**
> File paymentpreparationBatchDownloadV1(paymentpreparationBatchDownloadV1Request)


### Example

```typescript
import {
    ObjectPaymentpreparationApi,
    Configuration,
    PaymentpreparationBatchDownloadV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectPaymentpreparationApi(configuration);

let pkiPaymentpreparationID: number; // (default to undefined)
let paymentpreparationBatchDownloadV1Request: PaymentpreparationBatchDownloadV1Request; //

const { status, data } = await apiInstance.paymentpreparationBatchDownloadV1(
    pkiPaymentpreparationID,
    paymentpreparationBatchDownloadV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **paymentpreparationBatchDownloadV1Request** | **PaymentpreparationBatchDownloadV1Request**|  | |
| **pkiPaymentpreparationID** | [**number**] |  | defaults to undefined|


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

# **paymentpreparationGetAttachmentsV1**
> PaymentpreparationGetAttachmentsV1Response paymentpreparationGetAttachmentsV1()


### Example

```typescript
import {
    ObjectPaymentpreparationApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectPaymentpreparationApi(configuration);

let pkiPaymentpreparationID: number; // (default to undefined)

const { status, data } = await apiInstance.paymentpreparationGetAttachmentsV1(
    pkiPaymentpreparationID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiPaymentpreparationID** | [**number**] |  | defaults to undefined|


### Return type

**PaymentpreparationGetAttachmentsV1Response**

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

# **paymentpreparationImportIntoEDMV1**
> PaymentpreparationImportIntoEDMV1Response paymentpreparationImportIntoEDMV1(paymentpreparationImportIntoEDMV1Request)


### Example

```typescript
import {
    ObjectPaymentpreparationApi,
    Configuration,
    PaymentpreparationImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectPaymentpreparationApi(configuration);

let pkiPaymentpreparationID: number; // (default to undefined)
let paymentpreparationImportIntoEDMV1Request: PaymentpreparationImportIntoEDMV1Request; //

const { status, data } = await apiInstance.paymentpreparationImportIntoEDMV1(
    pkiPaymentpreparationID,
    paymentpreparationImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **paymentpreparationImportIntoEDMV1Request** | **PaymentpreparationImportIntoEDMV1Request**|  | |
| **pkiPaymentpreparationID** | [**number**] |  | defaults to undefined|


### Return type

**PaymentpreparationImportIntoEDMV1Response**

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

