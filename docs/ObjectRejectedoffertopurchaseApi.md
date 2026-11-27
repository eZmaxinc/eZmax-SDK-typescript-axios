# ObjectRejectedoffertopurchaseApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**rejectedoffertopurchaseBatchDownloadV1**](#rejectedoffertopurchasebatchdownloadv1) | **POST** /1/object/rejectedoffertopurchase/{pkiRejectedoffertopurchaseID}/batchDownload | Download multiples attachments from a Rejectedoffertopurchase|
|[**rejectedoffertopurchaseGetAttachmentsV1**](#rejectedoffertopurchasegetattachmentsv1) | **GET** /1/object/rejectedoffertopurchase/{pkiRejectedoffertopurchaseID}/getAttachments | Retrieve Rejectedoffertopurchase\&#39;s attachments|
|[**rejectedoffertopurchaseGetCommunicationCountV1**](#rejectedoffertopurchasegetcommunicationcountv1) | **GET** /1/object/rejectedoffertopurchase/{pkiRejectedoffertopurchaseID}/getCommunicationCount | Retrieve Communication count|
|[**rejectedoffertopurchaseGetCommunicationListV1**](#rejectedoffertopurchasegetcommunicationlistv1) | **GET** /1/object/rejectedoffertopurchase/{pkiRejectedoffertopurchaseID}/getCommunicationList | Retrieve Communication list|
|[**rejectedoffertopurchaseGetCommunicationrecipientsV1**](#rejectedoffertopurchasegetcommunicationrecipientsv1) | **GET** /1/object/rejectedoffertopurchase/{pkiRejectedoffertopurchaseID}/getCommunicationrecipients | Retrieve Rejectedoffertopurchase\&#39;s Communicationrecipient|
|[**rejectedoffertopurchaseGetCommunicationsendersV1**](#rejectedoffertopurchasegetcommunicationsendersv1) | **GET** /1/object/rejectedoffertopurchase/{pkiRejectedoffertopurchaseID}/getCommunicationsenders | Retrieve Rejectedoffertopurchase\&#39;s Communicationsender|
|[**rejectedoffertopurchaseGetListV1**](#rejectedoffertopurchasegetlistv1) | **GET** /1/object/rejectedoffertopurchase/getList | Retrieve Rejectedoffertopurchase list|
|[**rejectedoffertopurchaseImportIntoEDMV1**](#rejectedoffertopurchaseimportintoedmv1) | **POST** /1/object/rejectedoffertopurchase/{pkiRejectedoffertopurchaseID}/importIntoEDM | Import attachments into the Rejectedoffertopurchase|

# **rejectedoffertopurchaseBatchDownloadV1**
> File rejectedoffertopurchaseBatchDownloadV1(rejectedoffertopurchaseBatchDownloadV1Request)


### Example

```typescript
import {
    ObjectRejectedoffertopurchaseApi,
    Configuration,
    RejectedoffertopurchaseBatchDownloadV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectRejectedoffertopurchaseApi(configuration);

let pkiRejectedoffertopurchaseID: number; // (default to undefined)
let rejectedoffertopurchaseBatchDownloadV1Request: RejectedoffertopurchaseBatchDownloadV1Request; //

const { status, data } = await apiInstance.rejectedoffertopurchaseBatchDownloadV1(
    pkiRejectedoffertopurchaseID,
    rejectedoffertopurchaseBatchDownloadV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **rejectedoffertopurchaseBatchDownloadV1Request** | **RejectedoffertopurchaseBatchDownloadV1Request**|  | |
| **pkiRejectedoffertopurchaseID** | [**number**] |  | defaults to undefined|


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

# **rejectedoffertopurchaseGetAttachmentsV1**
> RejectedoffertopurchaseGetAttachmentsV1Response rejectedoffertopurchaseGetAttachmentsV1()


### Example

```typescript
import {
    ObjectRejectedoffertopurchaseApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectRejectedoffertopurchaseApi(configuration);

let pkiRejectedoffertopurchaseID: number; // (default to undefined)

const { status, data } = await apiInstance.rejectedoffertopurchaseGetAttachmentsV1(
    pkiRejectedoffertopurchaseID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiRejectedoffertopurchaseID** | [**number**] |  | defaults to undefined|


### Return type

**RejectedoffertopurchaseGetAttachmentsV1Response**

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

# **rejectedoffertopurchaseGetCommunicationCountV1**
> RejectedoffertopurchaseGetCommunicationCountV1Response rejectedoffertopurchaseGetCommunicationCountV1()



### Example

```typescript
import {
    ObjectRejectedoffertopurchaseApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectRejectedoffertopurchaseApi(configuration);

let pkiRejectedoffertopurchaseID: number; // (default to undefined)

const { status, data } = await apiInstance.rejectedoffertopurchaseGetCommunicationCountV1(
    pkiRejectedoffertopurchaseID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiRejectedoffertopurchaseID** | [**number**] |  | defaults to undefined|


### Return type

**RejectedoffertopurchaseGetCommunicationCountV1Response**

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

# **rejectedoffertopurchaseGetCommunicationListV1**
> RejectedoffertopurchaseGetCommunicationListV1Response rejectedoffertopurchaseGetCommunicationListV1()



### Example

```typescript
import {
    ObjectRejectedoffertopurchaseApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectRejectedoffertopurchaseApi(configuration);

let pkiRejectedoffertopurchaseID: number; // (default to undefined)

const { status, data } = await apiInstance.rejectedoffertopurchaseGetCommunicationListV1(
    pkiRejectedoffertopurchaseID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiRejectedoffertopurchaseID** | [**number**] |  | defaults to undefined|


### Return type

**RejectedoffertopurchaseGetCommunicationListV1Response**

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

# **rejectedoffertopurchaseGetCommunicationrecipientsV1**
> RejectedoffertopurchaseGetCommunicationrecipientsV1Response rejectedoffertopurchaseGetCommunicationrecipientsV1()



### Example

```typescript
import {
    ObjectRejectedoffertopurchaseApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectRejectedoffertopurchaseApi(configuration);

let pkiRejectedoffertopurchaseID: number; // (default to undefined)

const { status, data } = await apiInstance.rejectedoffertopurchaseGetCommunicationrecipientsV1(
    pkiRejectedoffertopurchaseID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiRejectedoffertopurchaseID** | [**number**] |  | defaults to undefined|


### Return type

**RejectedoffertopurchaseGetCommunicationrecipientsV1Response**

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

# **rejectedoffertopurchaseGetCommunicationsendersV1**
> RejectedoffertopurchaseGetCommunicationsendersV1Response rejectedoffertopurchaseGetCommunicationsendersV1()



### Example

```typescript
import {
    ObjectRejectedoffertopurchaseApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectRejectedoffertopurchaseApi(configuration);

let pkiRejectedoffertopurchaseID: number; // (default to undefined)

const { status, data } = await apiInstance.rejectedoffertopurchaseGetCommunicationsendersV1(
    pkiRejectedoffertopurchaseID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiRejectedoffertopurchaseID** | [**number**] |  | defaults to undefined|


### Return type

**RejectedoffertopurchaseGetCommunicationsendersV1Response**

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

# **rejectedoffertopurchaseGetListV1**
> RejectedoffertopurchaseGetListV1Response rejectedoffertopurchaseGetListV1()



### Example

```typescript
import {
    ObjectRejectedoffertopurchaseApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectRejectedoffertopurchaseApi(configuration);

let eOrderBy: 'pkiRejectedoffertopurchaseID_ASC' | 'pkiRejectedoffertopurchaseID_DESC' | 'sRejectedoffertopurchaseNumber_ASC' | 'sRejectedoffertopurchaseNumber_DESC' | 'dtRejectedoffertopurchaseDate_ASC' | 'dtRejectedoffertopurchaseDate_DESC' | 'bRejectedoffertopurchaseIsactive_ASC' | 'bRejectedoffertopurchaseIsactive_DESC' | 'bRejectedoffertopurchaseLinkedtoinscription_ASC' | 'bRejectedoffertopurchaseLinkedtoinscription_DESC' | 'dtCreatedDate_ASC' | 'dtCreatedDate_DESC' | 'sAddressCivic_ASC' | 'sAddressCivic_DESC' | 'sAddressStreet_ASC' | 'sAddressStreet_DESC' | 'sAddressSuite_ASC' | 'sAddressSuite_DESC' | 'sAddressCity_ASC' | 'sAddressCity_DESC' | 'sAddressZip_ASC' | 'sAddressZip_DESC' | 'sProvinceNameX_ASC' | 'sProvinceNameX_DESC' | 'sCountryNameX_ASC' | 'sCountryNameX_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.rejectedoffertopurchaseGetListV1(
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
| **eOrderBy** | [**&#39;pkiRejectedoffertopurchaseID_ASC&#39; | &#39;pkiRejectedoffertopurchaseID_DESC&#39; | &#39;sRejectedoffertopurchaseNumber_ASC&#39; | &#39;sRejectedoffertopurchaseNumber_DESC&#39; | &#39;dtRejectedoffertopurchaseDate_ASC&#39; | &#39;dtRejectedoffertopurchaseDate_DESC&#39; | &#39;bRejectedoffertopurchaseIsactive_ASC&#39; | &#39;bRejectedoffertopurchaseIsactive_DESC&#39; | &#39;bRejectedoffertopurchaseLinkedtoinscription_ASC&#39; | &#39;bRejectedoffertopurchaseLinkedtoinscription_DESC&#39; | &#39;dtCreatedDate_ASC&#39; | &#39;dtCreatedDate_DESC&#39; | &#39;sAddressCivic_ASC&#39; | &#39;sAddressCivic_DESC&#39; | &#39;sAddressStreet_ASC&#39; | &#39;sAddressStreet_DESC&#39; | &#39;sAddressSuite_ASC&#39; | &#39;sAddressSuite_DESC&#39; | &#39;sAddressCity_ASC&#39; | &#39;sAddressCity_DESC&#39; | &#39;sAddressZip_ASC&#39; | &#39;sAddressZip_DESC&#39; | &#39;sProvinceNameX_ASC&#39; | &#39;sProvinceNameX_DESC&#39; | &#39;sCountryNameX_ASC&#39; | &#39;sCountryNameX_DESC&#39;**]**Array<&#39;pkiRejectedoffertopurchaseID_ASC&#39; &#124; &#39;pkiRejectedoffertopurchaseID_DESC&#39; &#124; &#39;sRejectedoffertopurchaseNumber_ASC&#39; &#124; &#39;sRejectedoffertopurchaseNumber_DESC&#39; &#124; &#39;dtRejectedoffertopurchaseDate_ASC&#39; &#124; &#39;dtRejectedoffertopurchaseDate_DESC&#39; &#124; &#39;bRejectedoffertopurchaseIsactive_ASC&#39; &#124; &#39;bRejectedoffertopurchaseIsactive_DESC&#39; &#124; &#39;bRejectedoffertopurchaseLinkedtoinscription_ASC&#39; &#124; &#39;bRejectedoffertopurchaseLinkedtoinscription_DESC&#39; &#124; &#39;dtCreatedDate_ASC&#39; &#124; &#39;dtCreatedDate_DESC&#39; &#124; &#39;sAddressCivic_ASC&#39; &#124; &#39;sAddressCivic_DESC&#39; &#124; &#39;sAddressStreet_ASC&#39; &#124; &#39;sAddressStreet_DESC&#39; &#124; &#39;sAddressSuite_ASC&#39; &#124; &#39;sAddressSuite_DESC&#39; &#124; &#39;sAddressCity_ASC&#39; &#124; &#39;sAddressCity_DESC&#39; &#124; &#39;sAddressZip_ASC&#39; &#124; &#39;sAddressZip_DESC&#39; &#124; &#39;sProvinceNameX_ASC&#39; &#124; &#39;sProvinceNameX_DESC&#39; &#124; &#39;sCountryNameX_ASC&#39; &#124; &#39;sCountryNameX_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**RejectedoffertopurchaseGetListV1Response**

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

# **rejectedoffertopurchaseImportIntoEDMV1**
> RejectedoffertopurchaseImportIntoEDMV1Response rejectedoffertopurchaseImportIntoEDMV1(rejectedoffertopurchaseImportIntoEDMV1Request)



### Example

```typescript
import {
    ObjectRejectedoffertopurchaseApi,
    Configuration,
    RejectedoffertopurchaseImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectRejectedoffertopurchaseApi(configuration);

let pkiRejectedoffertopurchaseID: number; // (default to undefined)
let rejectedoffertopurchaseImportIntoEDMV1Request: RejectedoffertopurchaseImportIntoEDMV1Request; //

const { status, data } = await apiInstance.rejectedoffertopurchaseImportIntoEDMV1(
    pkiRejectedoffertopurchaseID,
    rejectedoffertopurchaseImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **rejectedoffertopurchaseImportIntoEDMV1Request** | **RejectedoffertopurchaseImportIntoEDMV1Request**|  | |
| **pkiRejectedoffertopurchaseID** | [**number**] |  | defaults to undefined|


### Return type

**RejectedoffertopurchaseImportIntoEDMV1Response**

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

