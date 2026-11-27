# ObjectBuyercontractApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**buyercontractBatchDownloadV1**](#buyercontractbatchdownloadv1) | **POST** /1/object/buyercontract/{pkiBuyercontractID}/batchDownload | Download multiples attachments from a Buyercontract|
|[**buyercontractGetAttachmentsV1**](#buyercontractgetattachmentsv1) | **GET** /1/object/buyercontract/{pkiBuyercontractID}/getAttachments | Retrieve Buyercontract\&#39;s attachments|
|[**buyercontractGetCommunicationCountV1**](#buyercontractgetcommunicationcountv1) | **GET** /1/object/buyercontract/{pkiBuyercontractID}/getCommunicationCount | Retrieve Communication count|
|[**buyercontractGetCommunicationListV1**](#buyercontractgetcommunicationlistv1) | **GET** /1/object/buyercontract/{pkiBuyercontractID}/getCommunicationList | Retrieve Communication list|
|[**buyercontractGetCommunicationrecipientsV1**](#buyercontractgetcommunicationrecipientsv1) | **GET** /1/object/buyercontract/{pkiBuyercontractID}/getCommunicationrecipients | Retrieve Buyercontract\&#39;s Communicationrecipient|
|[**buyercontractGetCommunicationsendersV1**](#buyercontractgetcommunicationsendersv1) | **GET** /1/object/buyercontract/{pkiBuyercontractID}/getCommunicationsenders | Retrieve Buyercontract\&#39;s Communicationsender|
|[**buyercontractGetListV1**](#buyercontractgetlistv1) | **GET** /1/object/buyercontract/getList | Retrieve Buyercontract list|
|[**buyercontractImportIntoEDMV1**](#buyercontractimportintoedmv1) | **POST** /1/object/buyercontract/{pkiBuyercontractID}/importIntoEDM | Import attachments into the Buyercontract|

# **buyercontractBatchDownloadV1**
> File buyercontractBatchDownloadV1(buyercontractBatchDownloadV1Request)


### Example

```typescript
import {
    ObjectBuyercontractApi,
    Configuration,
    BuyercontractBatchDownloadV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBuyercontractApi(configuration);

let pkiBuyercontractID: number; // (default to undefined)
let buyercontractBatchDownloadV1Request: BuyercontractBatchDownloadV1Request; //

const { status, data } = await apiInstance.buyercontractBatchDownloadV1(
    pkiBuyercontractID,
    buyercontractBatchDownloadV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **buyercontractBatchDownloadV1Request** | **BuyercontractBatchDownloadV1Request**|  | |
| **pkiBuyercontractID** | [**number**] |  | defaults to undefined|


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

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **buyercontractGetAttachmentsV1**
> BuyercontractGetAttachmentsV1Response buyercontractGetAttachmentsV1()


### Example

```typescript
import {
    ObjectBuyercontractApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBuyercontractApi(configuration);

let pkiBuyercontractID: number; // (default to undefined)

const { status, data } = await apiInstance.buyercontractGetAttachmentsV1(
    pkiBuyercontractID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiBuyercontractID** | [**number**] |  | defaults to undefined|


### Return type

**BuyercontractGetAttachmentsV1Response**

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

# **buyercontractGetCommunicationCountV1**
> BuyercontractGetCommunicationCountV1Response buyercontractGetCommunicationCountV1()



### Example

```typescript
import {
    ObjectBuyercontractApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBuyercontractApi(configuration);

let pkiBuyercontractID: number; // (default to undefined)

const { status, data } = await apiInstance.buyercontractGetCommunicationCountV1(
    pkiBuyercontractID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiBuyercontractID** | [**number**] |  | defaults to undefined|


### Return type

**BuyercontractGetCommunicationCountV1Response**

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

# **buyercontractGetCommunicationListV1**
> BuyercontractGetCommunicationListV1Response buyercontractGetCommunicationListV1()



### Example

```typescript
import {
    ObjectBuyercontractApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBuyercontractApi(configuration);

let pkiBuyercontractID: number; // (default to undefined)

const { status, data } = await apiInstance.buyercontractGetCommunicationListV1(
    pkiBuyercontractID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiBuyercontractID** | [**number**] |  | defaults to undefined|


### Return type

**BuyercontractGetCommunicationListV1Response**

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

# **buyercontractGetCommunicationrecipientsV1**
> BuyercontractGetCommunicationrecipientsV1Response buyercontractGetCommunicationrecipientsV1()



### Example

```typescript
import {
    ObjectBuyercontractApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBuyercontractApi(configuration);

let pkiBuyercontractID: number; // (default to undefined)

const { status, data } = await apiInstance.buyercontractGetCommunicationrecipientsV1(
    pkiBuyercontractID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiBuyercontractID** | [**number**] |  | defaults to undefined|


### Return type

**BuyercontractGetCommunicationrecipientsV1Response**

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

# **buyercontractGetCommunicationsendersV1**
> BuyercontractGetCommunicationsendersV1Response buyercontractGetCommunicationsendersV1()



### Example

```typescript
import {
    ObjectBuyercontractApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBuyercontractApi(configuration);

let pkiBuyercontractID: number; // (default to undefined)

const { status, data } = await apiInstance.buyercontractGetCommunicationsendersV1(
    pkiBuyercontractID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiBuyercontractID** | [**number**] |  | defaults to undefined|


### Return type

**BuyercontractGetCommunicationsendersV1Response**

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

# **buyercontractGetListV1**
> BuyercontractGetListV1Response buyercontractGetListV1()

Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eBuyercontractStep | Imported<br>Active<br>Modified<br>ContractEnded<br>ExpiredContract<br>Bought | | eBuyercontractType | Rent<br>Sale<br>RentOrSale |

### Example

```typescript
import {
    ObjectBuyercontractApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBuyercontractApi(configuration);

let eOrderBy: 'pkiBuyercontractID_ASC' | 'pkiBuyercontractID_DESC' | 'fkiInscriptiontypeID_ASC' | 'fkiInscriptiontypeID_DESC' | 'sInscriptiontypeNameX_ASC' | 'sInscriptiontypeNameX_DESC' | 'eBuyercontractStep_ASC' | 'eBuyercontractStep_DESC' | 'dBuyercontractMinimumprice_ASC' | 'dBuyercontractMinimumprice_DESC' | 'dBuyercontractMaximumprice_ASC' | 'dBuyercontractMaximumprice_DESC' | 'eBuyercontractType_ASC' | 'eBuyercontractType_DESC' | 'dtBuyercontractDate_ASC' | 'dtBuyercontractDate_DESC' | 'dtBuyercontractExpirationdate_ASC' | 'dtBuyercontractExpirationdate_DESC' | 'bBuyercontractIsactive_ASC' | 'bBuyercontractIsactive_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.buyercontractGetListV1(
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
| **eOrderBy** | [**&#39;pkiBuyercontractID_ASC&#39; | &#39;pkiBuyercontractID_DESC&#39; | &#39;fkiInscriptiontypeID_ASC&#39; | &#39;fkiInscriptiontypeID_DESC&#39; | &#39;sInscriptiontypeNameX_ASC&#39; | &#39;sInscriptiontypeNameX_DESC&#39; | &#39;eBuyercontractStep_ASC&#39; | &#39;eBuyercontractStep_DESC&#39; | &#39;dBuyercontractMinimumprice_ASC&#39; | &#39;dBuyercontractMinimumprice_DESC&#39; | &#39;dBuyercontractMaximumprice_ASC&#39; | &#39;dBuyercontractMaximumprice_DESC&#39; | &#39;eBuyercontractType_ASC&#39; | &#39;eBuyercontractType_DESC&#39; | &#39;dtBuyercontractDate_ASC&#39; | &#39;dtBuyercontractDate_DESC&#39; | &#39;dtBuyercontractExpirationdate_ASC&#39; | &#39;dtBuyercontractExpirationdate_DESC&#39; | &#39;bBuyercontractIsactive_ASC&#39; | &#39;bBuyercontractIsactive_DESC&#39;**]**Array<&#39;pkiBuyercontractID_ASC&#39; &#124; &#39;pkiBuyercontractID_DESC&#39; &#124; &#39;fkiInscriptiontypeID_ASC&#39; &#124; &#39;fkiInscriptiontypeID_DESC&#39; &#124; &#39;sInscriptiontypeNameX_ASC&#39; &#124; &#39;sInscriptiontypeNameX_DESC&#39; &#124; &#39;eBuyercontractStep_ASC&#39; &#124; &#39;eBuyercontractStep_DESC&#39; &#124; &#39;dBuyercontractMinimumprice_ASC&#39; &#124; &#39;dBuyercontractMinimumprice_DESC&#39; &#124; &#39;dBuyercontractMaximumprice_ASC&#39; &#124; &#39;dBuyercontractMaximumprice_DESC&#39; &#124; &#39;eBuyercontractType_ASC&#39; &#124; &#39;eBuyercontractType_DESC&#39; &#124; &#39;dtBuyercontractDate_ASC&#39; &#124; &#39;dtBuyercontractDate_DESC&#39; &#124; &#39;dtBuyercontractExpirationdate_ASC&#39; &#124; &#39;dtBuyercontractExpirationdate_DESC&#39; &#124; &#39;bBuyercontractIsactive_ASC&#39; &#124; &#39;bBuyercontractIsactive_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**BuyercontractGetListV1Response**

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

# **buyercontractImportIntoEDMV1**
> BuyercontractImportIntoEDMV1Response buyercontractImportIntoEDMV1(buyercontractImportIntoEDMV1Request)



### Example

```typescript
import {
    ObjectBuyercontractApi,
    Configuration,
    BuyercontractImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBuyercontractApi(configuration);

let pkiBuyercontractID: number; // (default to undefined)
let buyercontractImportIntoEDMV1Request: BuyercontractImportIntoEDMV1Request; //

const { status, data } = await apiInstance.buyercontractImportIntoEDMV1(
    pkiBuyercontractID,
    buyercontractImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **buyercontractImportIntoEDMV1Request** | **BuyercontractImportIntoEDMV1Request**|  | |
| **pkiBuyercontractID** | [**number**] |  | defaults to undefined|


### Return type

**BuyercontractImportIntoEDMV1Response**

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

