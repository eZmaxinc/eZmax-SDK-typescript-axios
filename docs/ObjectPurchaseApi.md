# ObjectPurchaseApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**purchaseBatchDownloadV1**](#purchasebatchdownloadv1) | **POST** /1/object/purchase/{pkiPurchaseID}/batchDownload | Download multiples attachments from a Purchase|
|[**purchaseGetAttachmentsV1**](#purchasegetattachmentsv1) | **GET** /1/object/purchase/{pkiPurchaseID}/getAttachments | Retrieve Purchase\&#39;s attachments|
|[**purchaseGetCommunicationCountV1**](#purchasegetcommunicationcountv1) | **GET** /1/object/purchase/{pkiPurchaseID}/getCommunicationCount | Retrieve Communication count|
|[**purchaseGetCommunicationListV1**](#purchasegetcommunicationlistv1) | **GET** /1/object/purchase/{pkiPurchaseID}/getCommunicationList | Retrieve Communication list|
|[**purchaseGetCommunicationrecipientsV1**](#purchasegetcommunicationrecipientsv1) | **GET** /1/object/purchase/{pkiPurchaseID}/getCommunicationrecipients | Retrieve Communication recipients|
|[**purchaseGetCommunicationsendersV1**](#purchasegetcommunicationsendersv1) | **GET** /1/object/purchase/{pkiPurchaseID}/getCommunicationsenders | Retrieve Communication senders|
|[**purchaseGetListV1**](#purchasegetlistv1) | **GET** /1/object/purchase/getList | Retrieve Purchase list|
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

# **purchaseGetCommunicationCountV1**
> PurchaseGetCommunicationCountV1Response purchaseGetCommunicationCountV1()


### Example

```typescript
import {
    ObjectPurchaseApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectPurchaseApi(configuration);

let pkiPurchaseID: number; // (default to undefined)

const { status, data } = await apiInstance.purchaseGetCommunicationCountV1(
    pkiPurchaseID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiPurchaseID** | [**number**] |  | defaults to undefined|


### Return type

**PurchaseGetCommunicationCountV1Response**

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

# **purchaseGetCommunicationListV1**
> PurchaseGetCommunicationListV1Response purchaseGetCommunicationListV1()


### Example

```typescript
import {
    ObjectPurchaseApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectPurchaseApi(configuration);

let pkiPurchaseID: number; // (default to undefined)

const { status, data } = await apiInstance.purchaseGetCommunicationListV1(
    pkiPurchaseID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiPurchaseID** | [**number**] |  | defaults to undefined|


### Return type

**PurchaseGetCommunicationListV1Response**

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

# **purchaseGetCommunicationrecipientsV1**
> PurchaseGetCommunicationrecipientsV1Response purchaseGetCommunicationrecipientsV1()


### Example

```typescript
import {
    ObjectPurchaseApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectPurchaseApi(configuration);

let pkiPurchaseID: number; // (default to undefined)

const { status, data } = await apiInstance.purchaseGetCommunicationrecipientsV1(
    pkiPurchaseID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiPurchaseID** | [**number**] |  | defaults to undefined|


### Return type

**PurchaseGetCommunicationrecipientsV1Response**

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

# **purchaseGetCommunicationsendersV1**
> PurchaseGetCommunicationsendersV1Response purchaseGetCommunicationsendersV1()


### Example

```typescript
import {
    ObjectPurchaseApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectPurchaseApi(configuration);

let pkiPurchaseID: number; // (default to undefined)

const { status, data } = await apiInstance.purchaseGetCommunicationsendersV1(
    pkiPurchaseID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiPurchaseID** | [**number**] |  | defaults to undefined|


### Return type

**PurchaseGetCommunicationsendersV1Response**

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

# **purchaseGetListV1**
> PurchaseGetListV1Response purchaseGetListV1()



### Example

```typescript
import {
    ObjectPurchaseApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectPurchaseApi(configuration);

let eOrderBy: 'pkiPurchaseID_ASC' | 'pkiPurchaseID_DESC' | 'fkiFranchiseofficeID_ASC' | 'fkiFranchiseofficeID_DESC' | 'fkiSupplierID_ASC' | 'fkiSupplierID_DESC' | 'fkiPeriodID_ASC' | 'fkiPeriodID_DESC' | 'sPurchaseBillnumber_ASC' | 'sPurchaseBillnumber_DESC' | 'dtPurchaseDate_ASC' | 'dtPurchaseDate_DESC' | 'dtPurchasePaydate_ASC' | 'dtPurchasePaydate_DESC' | 'dPurchaseTotal_ASC' | 'dPurchaseTotal_DESC' | 'bPurchaseIsfinanced_ASC' | 'bPurchaseIsfinanced_DESC' | 'bPurchaseIspaid_ASC' | 'bPurchaseIspaid_DESC' | 'sFranchiseagenceName_ASC' | 'sFranchiseagenceName_DESC' | 'iFranchiseofficeCode_ASC' | 'iFranchiseofficeCode_DESC' | 'sSupplierName_ASC' | 'sSupplierName_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.purchaseGetListV1(
    eOrderBy,
    iRowMax,
    iRowOffset,
    acceptLanguage,
    sFilter
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **eOrderBy** | [**&#39;pkiPurchaseID_ASC&#39; | &#39;pkiPurchaseID_DESC&#39; | &#39;fkiFranchiseofficeID_ASC&#39; | &#39;fkiFranchiseofficeID_DESC&#39; | &#39;fkiSupplierID_ASC&#39; | &#39;fkiSupplierID_DESC&#39; | &#39;fkiPeriodID_ASC&#39; | &#39;fkiPeriodID_DESC&#39; | &#39;sPurchaseBillnumber_ASC&#39; | &#39;sPurchaseBillnumber_DESC&#39; | &#39;dtPurchaseDate_ASC&#39; | &#39;dtPurchaseDate_DESC&#39; | &#39;dtPurchasePaydate_ASC&#39; | &#39;dtPurchasePaydate_DESC&#39; | &#39;dPurchaseTotal_ASC&#39; | &#39;dPurchaseTotal_DESC&#39; | &#39;bPurchaseIsfinanced_ASC&#39; | &#39;bPurchaseIsfinanced_DESC&#39; | &#39;bPurchaseIspaid_ASC&#39; | &#39;bPurchaseIspaid_DESC&#39; | &#39;sFranchiseagenceName_ASC&#39; | &#39;sFranchiseagenceName_DESC&#39; | &#39;iFranchiseofficeCode_ASC&#39; | &#39;iFranchiseofficeCode_DESC&#39; | &#39;sSupplierName_ASC&#39; | &#39;sSupplierName_DESC&#39;**]**Array<&#39;pkiPurchaseID_ASC&#39; &#124; &#39;pkiPurchaseID_DESC&#39; &#124; &#39;fkiFranchiseofficeID_ASC&#39; &#124; &#39;fkiFranchiseofficeID_DESC&#39; &#124; &#39;fkiSupplierID_ASC&#39; &#124; &#39;fkiSupplierID_DESC&#39; &#124; &#39;fkiPeriodID_ASC&#39; &#124; &#39;fkiPeriodID_DESC&#39; &#124; &#39;sPurchaseBillnumber_ASC&#39; &#124; &#39;sPurchaseBillnumber_DESC&#39; &#124; &#39;dtPurchaseDate_ASC&#39; &#124; &#39;dtPurchaseDate_DESC&#39; &#124; &#39;dtPurchasePaydate_ASC&#39; &#124; &#39;dtPurchasePaydate_DESC&#39; &#124; &#39;dPurchaseTotal_ASC&#39; &#124; &#39;dPurchaseTotal_DESC&#39; &#124; &#39;bPurchaseIsfinanced_ASC&#39; &#124; &#39;bPurchaseIsfinanced_DESC&#39; &#124; &#39;bPurchaseIspaid_ASC&#39; &#124; &#39;bPurchaseIspaid_DESC&#39; &#124; &#39;sFranchiseagenceName_ASC&#39; &#124; &#39;sFranchiseagenceName_DESC&#39; &#124; &#39;iFranchiseofficeCode_ASC&#39; &#124; &#39;iFranchiseofficeCode_DESC&#39; &#124; &#39;sSupplierName_ASC&#39; &#124; &#39;sSupplierName_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**PurchaseGetListV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json, application/vnd.openxmlformats-officedocument.spreadsheetml.sheet


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**406** | The URL is valid, but one of the Accept header is not defined or invalid. For example, you set the header \&quot;Accept: application/json\&quot; but the function can only return \&quot;Content-type: image/png\&quot; |  -  |

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

