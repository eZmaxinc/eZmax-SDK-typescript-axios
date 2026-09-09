# ObjectPurchaseApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**purchaseBatchDownloadV1**](#purchasebatchdownloadv1) | **POST** /1/object/purchase/{pkiPurchaseID}/batchDownload | Download multiples attachments from a Purchase|
|[**purchaseGetAttachmentsV1**](#purchasegetattachmentsv1) | **GET** /1/object/purchase/{pkiPurchaseID}/getAttachments | Retrieve Purchase\&#39;s attachments|
|[**purchaseImportIntoEDMV1**](#purchaseimportintoedmv1) | **POST** /1/object/purchase/{pkiPurchaseID}/importIntoEDM | Import attachments into the Purchase|

# **purchaseBatchDownloadV1**
> File purchaseBatchDownloadV1(purchaseBatchDownloadV1Request)


### Example

```typescript
import {
    ObjectPurchaseApi,
    Configuration,
    PurchaseBatchDownloadV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectPurchaseApi(configuration);

let pkiPurchaseID: number; // (default to undefined)
let purchaseBatchDownloadV1Request: PurchaseBatchDownloadV1Request; //

const { status, data } = await apiInstance.purchaseBatchDownloadV1(
    pkiPurchaseID,
    purchaseBatchDownloadV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **purchaseBatchDownloadV1Request** | **PurchaseBatchDownloadV1Request**|  | |
| **pkiPurchaseID** | [**number**] |  | defaults to undefined|


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

# **purchaseGetAttachmentsV1**
> PurchaseGetAttachmentsV1Response purchaseGetAttachmentsV1()


### Example

```typescript
import {
    ObjectPurchaseApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectPurchaseApi(configuration);

let pkiPurchaseID: number; // (default to undefined)

const { status, data } = await apiInstance.purchaseGetAttachmentsV1(
    pkiPurchaseID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiPurchaseID** | [**number**] |  | defaults to undefined|


### Return type

**PurchaseGetAttachmentsV1Response**

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

# **purchaseImportIntoEDMV1**
> PurchaseImportIntoEDMV1Response purchaseImportIntoEDMV1(purchaseImportIntoEDMV1Request)


### Example

```typescript
import {
    ObjectPurchaseApi,
    Configuration,
    PurchaseImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectPurchaseApi(configuration);

let pkiPurchaseID: number; // (default to undefined)
let purchaseImportIntoEDMV1Request: PurchaseImportIntoEDMV1Request; //

const { status, data } = await apiInstance.purchaseImportIntoEDMV1(
    pkiPurchaseID,
    purchaseImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **purchaseImportIntoEDMV1Request** | **PurchaseImportIntoEDMV1Request**|  | |
| **pkiPurchaseID** | [**number**] |  | defaults to undefined|


### Return type

**PurchaseImportIntoEDMV1Response**

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

