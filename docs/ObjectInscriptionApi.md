# ObjectInscriptionApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**inscriptionBatchDownloadV1**](#inscriptionbatchdownloadv1) | **POST** /1/object/inscription/{pkiInscriptionID}/batchDownload | Download multiples attachments from an Inscription|
|[**inscriptionGetAttachmentsV1**](#inscriptiongetattachmentsv1) | **GET** /1/object/inscription/{pkiInscriptionID}/getAttachments | Retrieve Inscription\&#39;s Attachments|
|[**inscriptionGetCommunicationCountV1**](#inscriptiongetcommunicationcountv1) | **GET** /1/object/inscription/{pkiInscriptionID}/getCommunicationCount | Retrieve Communication count|
|[**inscriptionGetCommunicationListV1**](#inscriptiongetcommunicationlistv1) | **GET** /1/object/inscription/{pkiInscriptionID}/getCommunicationList | Retrieve Communication list|
|[**inscriptionGetCommunicationrecipientsV1**](#inscriptiongetcommunicationrecipientsv1) | **GET** /1/object/inscription/{pkiInscriptionID}/getCommunicationrecipients | Retrieve Inscription\&#39;s Communicationrecipient|
|[**inscriptionGetCommunicationsendersV1**](#inscriptiongetcommunicationsendersv1) | **GET** /1/object/inscription/{pkiInscriptionID}/getCommunicationsenders | Retrieve Inscription\&#39;s Communicationsender|
|[**inscriptionGetInscriptionnotauthenticatedsV1**](#inscriptiongetinscriptionnotauthenticatedsv1) | **GET** /1/object/inscription/{pkiInscriptionID}/getInscriptionnotauthenticateds | Retrieve Inscription\&#39;s Inscriptionnotauthenticated|
|[**inscriptionGetListV1**](#inscriptiongetlistv1) | **GET** /1/object/inscription/getList | Retrieve Inscription list|
|[**inscriptionGetObjectV2**](#inscriptiongetobjectv2) | **GET** /2/object/inscription/{pkiInscriptionID} | Retrieve an existing Inscription|
|[**inscriptionImportIntoEDMV1**](#inscriptionimportintoedmv1) | **POST** /1/object/inscription/{pkiInscriptionID}/importIntoEDM | Import attachments into the Inscription|
|[**inscriptionPrepareFilesTransferV1**](#inscriptionpreparefilestransferv1) | **POST** /1/object/inscription/{pkiInscriptionID}/prepareFilesTransfer | Prepares file transfer into EDM|

# **inscriptionBatchDownloadV1**
> File inscriptionBatchDownloadV1(inscriptionBatchDownloadV1Request)


### Example

```typescript
import {
    ObjectInscriptionApi,
    Configuration,
    InscriptionBatchDownloadV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInscriptionApi(configuration);

let pkiInscriptionID: number; // (default to undefined)
let inscriptionBatchDownloadV1Request: InscriptionBatchDownloadV1Request; //

const { status, data } = await apiInstance.inscriptionBatchDownloadV1(
    pkiInscriptionID,
    inscriptionBatchDownloadV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **inscriptionBatchDownloadV1Request** | **InscriptionBatchDownloadV1Request**|  | |
| **pkiInscriptionID** | [**number**] |  | defaults to undefined|


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

# **inscriptionGetAttachmentsV1**
> InscriptionGetAttachmentsV1Response inscriptionGetAttachmentsV1()



### Example

```typescript
import {
    ObjectInscriptionApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInscriptionApi(configuration);

let pkiInscriptionID: number; // (default to undefined)

const { status, data } = await apiInstance.inscriptionGetAttachmentsV1(
    pkiInscriptionID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiInscriptionID** | [**number**] |  | defaults to undefined|


### Return type

**InscriptionGetAttachmentsV1Response**

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

# **inscriptionGetCommunicationCountV1**
> InscriptionGetCommunicationCountV1Response inscriptionGetCommunicationCountV1()



### Example

```typescript
import {
    ObjectInscriptionApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInscriptionApi(configuration);

let pkiInscriptionID: number; // (default to undefined)

const { status, data } = await apiInstance.inscriptionGetCommunicationCountV1(
    pkiInscriptionID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiInscriptionID** | [**number**] |  | defaults to undefined|


### Return type

**InscriptionGetCommunicationCountV1Response**

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

# **inscriptionGetCommunicationListV1**
> InscriptionGetCommunicationListV1Response inscriptionGetCommunicationListV1()



### Example

```typescript
import {
    ObjectInscriptionApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInscriptionApi(configuration);

let pkiInscriptionID: number; // (default to undefined)

const { status, data } = await apiInstance.inscriptionGetCommunicationListV1(
    pkiInscriptionID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiInscriptionID** | [**number**] |  | defaults to undefined|


### Return type

**InscriptionGetCommunicationListV1Response**

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

# **inscriptionGetCommunicationrecipientsV1**
> InscriptionGetCommunicationrecipientsV1Response inscriptionGetCommunicationrecipientsV1()



### Example

```typescript
import {
    ObjectInscriptionApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInscriptionApi(configuration);

let pkiInscriptionID: number; // (default to undefined)

const { status, data } = await apiInstance.inscriptionGetCommunicationrecipientsV1(
    pkiInscriptionID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiInscriptionID** | [**number**] |  | defaults to undefined|


### Return type

**InscriptionGetCommunicationrecipientsV1Response**

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

# **inscriptionGetCommunicationsendersV1**
> InscriptionGetCommunicationsendersV1Response inscriptionGetCommunicationsendersV1()



### Example

```typescript
import {
    ObjectInscriptionApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInscriptionApi(configuration);

let pkiInscriptionID: number; // (default to undefined)

const { status, data } = await apiInstance.inscriptionGetCommunicationsendersV1(
    pkiInscriptionID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiInscriptionID** | [**number**] |  | defaults to undefined|


### Return type

**InscriptionGetCommunicationsendersV1Response**

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

# **inscriptionGetInscriptionnotauthenticatedsV1**
> InscriptionGetInscriptionnotauthenticatedsV1Response inscriptionGetInscriptionnotauthenticatedsV1()


### Example

```typescript
import {
    ObjectInscriptionApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInscriptionApi(configuration);

let pkiInscriptionID: number; // (default to undefined)

const { status, data } = await apiInstance.inscriptionGetInscriptionnotauthenticatedsV1(
    pkiInscriptionID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiInscriptionID** | [**number**] |  | defaults to undefined|


### Return type

**InscriptionGetInscriptionnotauthenticatedsV1Response**

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

# **inscriptionGetListV1**
> InscriptionGetListV1Response inscriptionGetListV1()

Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eInscriptionStep | TemporaryNotAuthenticated<br>ImportedInscription<br>Inscription<br>ModifiedInscription<br>ContractEnded<br>ExpiredInscription<br>Out-market<br>ImportedNotauthenticated<br>NotAuthenticated<br>ModifiedNotauthenticated<br>Authenticated |  Advanced filters that can be used in query parameter *sFilter*:  | Variable | |---| | sBrokerNameInscriptor | | sBrokerNameSeller | | sContactFirstnameAgentInscriptor | | sContactLastnameAgentInscriptor | | sContactFirstnameAgentSeller | | sContactLastnameAgentSeller |         | sContactFirstnameBuyer | | sContactLastnameBuyer | | sContactFirstnameSeller | | sContactLastnameSeller |  | sContactFirstnameNotaryBuyer | | sContactLastnameNotaryBuyer |  | sContactFirstnameNotarySeller | | sContactLastnameNotarySeller |  | sExternalbrokerName |

### Example

```typescript
import {
    ObjectInscriptionApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInscriptionApi(configuration);

let eOrderBy: 'pkiInscriptionID_ASC' | 'pkiInscriptionID_DESC' | 'pkiInscriptionnotauthenticatedID_ASC' | 'pkiInscriptionnotauthenticatedID_DESC' | 'fkiInscriptiontypeID_ASC' | 'fkiInscriptiontypeID_DESC' | 'sInscriptiontypeNameX_ASC' | 'sInscriptiontypeNameX_DESC' | 'eInscriptionStep_ASC' | 'eInscriptionStep_DESC' | 'sInscriptionCivicend_ASC' | 'sInscriptionCivicend_DESC' | 'sInscriptionMLS_ASC' | 'sInscriptionMLS_DESC' | 'dInscriptionSaleprice_ASC' | 'dInscriptionSaleprice_DESC' | 'dInscriptionRentprice_ASC' | 'dInscriptionRentprice_DESC' | 'dtInscriptionDate_ASC' | 'dtInscriptionDate_DESC' | 'dtInscriptionExpirationdate_ASC' | 'dtInscriptionExpirationdate_DESC' | 'dtInscriptionNotarydate_ASC' | 'dtInscriptionNotarydate_DESC' | 'bInscriptionInspection_ASC' | 'bInscriptionInspection_DESC' | 'bInscriptionIsactive_ASC' | 'bInscriptionIsactive_DESC' | 'dtInscriptionnotauthenticatedNotaryscheduledate_ASC' | 'dtInscriptionnotauthenticatedNotaryscheduledate_DESC' | 'dtInscriptionnotauthenticatedTransactiondate_ASC' | 'dtInscriptionnotauthenticatedTransactiondate_DESC' | 'dtInscriptionnotauthenticatedTransactiondateReal_ASC' | 'dtInscriptionnotauthenticatedTransactiondateReal_DESC' | 'bInscriptionnotauthenticatedConditional_ASC' | 'bInscriptionnotauthenticatedConditional_DESC' | 'bInscriptionnotauthenticatedIsactive_ASC' | 'bInscriptionnotauthenticatedIsactive_DESC' | 'sAddressCivic_ASC' | 'sAddressCivic_DESC' | 'sAddressStreet_ASC' | 'sAddressStreet_DESC' | 'sAddressSuite_ASC' | 'sAddressSuite_DESC' | 'sAddressCity_ASC' | 'sAddressCity_DESC' | 'sAddressZip_ASC' | 'sAddressZip_DESC' | 'sProvinceNameX_ASC' | 'sProvinceNameX_DESC' | 'sCountryNameX_ASC' | 'sCountryNameX_DESC' | 'iInscriptionnotauthenticatedCanceled_ASC' | 'iInscriptionnotauthenticatedCanceled_DESC' | 'bAllowedCopyintoinscriptionedm_ASC' | 'bAllowedCopyintoinscriptionedm_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.inscriptionGetListV1(
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
| **eOrderBy** | [**&#39;pkiInscriptionID_ASC&#39; | &#39;pkiInscriptionID_DESC&#39; | &#39;pkiInscriptionnotauthenticatedID_ASC&#39; | &#39;pkiInscriptionnotauthenticatedID_DESC&#39; | &#39;fkiInscriptiontypeID_ASC&#39; | &#39;fkiInscriptiontypeID_DESC&#39; | &#39;sInscriptiontypeNameX_ASC&#39; | &#39;sInscriptiontypeNameX_DESC&#39; | &#39;eInscriptionStep_ASC&#39; | &#39;eInscriptionStep_DESC&#39; | &#39;sInscriptionCivicend_ASC&#39; | &#39;sInscriptionCivicend_DESC&#39; | &#39;sInscriptionMLS_ASC&#39; | &#39;sInscriptionMLS_DESC&#39; | &#39;dInscriptionSaleprice_ASC&#39; | &#39;dInscriptionSaleprice_DESC&#39; | &#39;dInscriptionRentprice_ASC&#39; | &#39;dInscriptionRentprice_DESC&#39; | &#39;dtInscriptionDate_ASC&#39; | &#39;dtInscriptionDate_DESC&#39; | &#39;dtInscriptionExpirationdate_ASC&#39; | &#39;dtInscriptionExpirationdate_DESC&#39; | &#39;dtInscriptionNotarydate_ASC&#39; | &#39;dtInscriptionNotarydate_DESC&#39; | &#39;bInscriptionInspection_ASC&#39; | &#39;bInscriptionInspection_DESC&#39; | &#39;bInscriptionIsactive_ASC&#39; | &#39;bInscriptionIsactive_DESC&#39; | &#39;dtInscriptionnotauthenticatedNotaryscheduledate_ASC&#39; | &#39;dtInscriptionnotauthenticatedNotaryscheduledate_DESC&#39; | &#39;dtInscriptionnotauthenticatedTransactiondate_ASC&#39; | &#39;dtInscriptionnotauthenticatedTransactiondate_DESC&#39; | &#39;dtInscriptionnotauthenticatedTransactiondateReal_ASC&#39; | &#39;dtInscriptionnotauthenticatedTransactiondateReal_DESC&#39; | &#39;bInscriptionnotauthenticatedConditional_ASC&#39; | &#39;bInscriptionnotauthenticatedConditional_DESC&#39; | &#39;bInscriptionnotauthenticatedIsactive_ASC&#39; | &#39;bInscriptionnotauthenticatedIsactive_DESC&#39; | &#39;sAddressCivic_ASC&#39; | &#39;sAddressCivic_DESC&#39; | &#39;sAddressStreet_ASC&#39; | &#39;sAddressStreet_DESC&#39; | &#39;sAddressSuite_ASC&#39; | &#39;sAddressSuite_DESC&#39; | &#39;sAddressCity_ASC&#39; | &#39;sAddressCity_DESC&#39; | &#39;sAddressZip_ASC&#39; | &#39;sAddressZip_DESC&#39; | &#39;sProvinceNameX_ASC&#39; | &#39;sProvinceNameX_DESC&#39; | &#39;sCountryNameX_ASC&#39; | &#39;sCountryNameX_DESC&#39; | &#39;iInscriptionnotauthenticatedCanceled_ASC&#39; | &#39;iInscriptionnotauthenticatedCanceled_DESC&#39; | &#39;bAllowedCopyintoinscriptionedm_ASC&#39; | &#39;bAllowedCopyintoinscriptionedm_DESC&#39;**]**Array<&#39;pkiInscriptionID_ASC&#39; &#124; &#39;pkiInscriptionID_DESC&#39; &#124; &#39;pkiInscriptionnotauthenticatedID_ASC&#39; &#124; &#39;pkiInscriptionnotauthenticatedID_DESC&#39; &#124; &#39;fkiInscriptiontypeID_ASC&#39; &#124; &#39;fkiInscriptiontypeID_DESC&#39; &#124; &#39;sInscriptiontypeNameX_ASC&#39; &#124; &#39;sInscriptiontypeNameX_DESC&#39; &#124; &#39;eInscriptionStep_ASC&#39; &#124; &#39;eInscriptionStep_DESC&#39; &#124; &#39;sInscriptionCivicend_ASC&#39; &#124; &#39;sInscriptionCivicend_DESC&#39; &#124; &#39;sInscriptionMLS_ASC&#39; &#124; &#39;sInscriptionMLS_DESC&#39; &#124; &#39;dInscriptionSaleprice_ASC&#39; &#124; &#39;dInscriptionSaleprice_DESC&#39; &#124; &#39;dInscriptionRentprice_ASC&#39; &#124; &#39;dInscriptionRentprice_DESC&#39; &#124; &#39;dtInscriptionDate_ASC&#39; &#124; &#39;dtInscriptionDate_DESC&#39; &#124; &#39;dtInscriptionExpirationdate_ASC&#39; &#124; &#39;dtInscriptionExpirationdate_DESC&#39; &#124; &#39;dtInscriptionNotarydate_ASC&#39; &#124; &#39;dtInscriptionNotarydate_DESC&#39; &#124; &#39;bInscriptionInspection_ASC&#39; &#124; &#39;bInscriptionInspection_DESC&#39; &#124; &#39;bInscriptionIsactive_ASC&#39; &#124; &#39;bInscriptionIsactive_DESC&#39; &#124; &#39;dtInscriptionnotauthenticatedNotaryscheduledate_ASC&#39; &#124; &#39;dtInscriptionnotauthenticatedNotaryscheduledate_DESC&#39; &#124; &#39;dtInscriptionnotauthenticatedTransactiondate_ASC&#39; &#124; &#39;dtInscriptionnotauthenticatedTransactiondate_DESC&#39; &#124; &#39;dtInscriptionnotauthenticatedTransactiondateReal_ASC&#39; &#124; &#39;dtInscriptionnotauthenticatedTransactiondateReal_DESC&#39; &#124; &#39;bInscriptionnotauthenticatedConditional_ASC&#39; &#124; &#39;bInscriptionnotauthenticatedConditional_DESC&#39; &#124; &#39;bInscriptionnotauthenticatedIsactive_ASC&#39; &#124; &#39;bInscriptionnotauthenticatedIsactive_DESC&#39; &#124; &#39;sAddressCivic_ASC&#39; &#124; &#39;sAddressCivic_DESC&#39; &#124; &#39;sAddressStreet_ASC&#39; &#124; &#39;sAddressStreet_DESC&#39; &#124; &#39;sAddressSuite_ASC&#39; &#124; &#39;sAddressSuite_DESC&#39; &#124; &#39;sAddressCity_ASC&#39; &#124; &#39;sAddressCity_DESC&#39; &#124; &#39;sAddressZip_ASC&#39; &#124; &#39;sAddressZip_DESC&#39; &#124; &#39;sProvinceNameX_ASC&#39; &#124; &#39;sProvinceNameX_DESC&#39; &#124; &#39;sCountryNameX_ASC&#39; &#124; &#39;sCountryNameX_DESC&#39; &#124; &#39;iInscriptionnotauthenticatedCanceled_ASC&#39; &#124; &#39;iInscriptionnotauthenticatedCanceled_DESC&#39; &#124; &#39;bAllowedCopyintoinscriptionedm_ASC&#39; &#124; &#39;bAllowedCopyintoinscriptionedm_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**InscriptionGetListV1Response**

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

# **inscriptionGetObjectV2**
> InscriptionGetObjectV2Response inscriptionGetObjectV2()



### Example

```typescript
import {
    ObjectInscriptionApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInscriptionApi(configuration);

let pkiInscriptionID: number; //The unique ID of the Inscription (default to undefined)

const { status, data } = await apiInstance.inscriptionGetObjectV2(
    pkiInscriptionID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiInscriptionID** | [**number**] | The unique ID of the Inscription | defaults to undefined|


### Return type

**InscriptionGetObjectV2Response**

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

# **inscriptionImportIntoEDMV1**
> InscriptionImportIntoEDMV1Response inscriptionImportIntoEDMV1(inscriptionImportIntoEDMV1Request)



### Example

```typescript
import {
    ObjectInscriptionApi,
    Configuration,
    InscriptionImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInscriptionApi(configuration);

let pkiInscriptionID: number; // (default to undefined)
let inscriptionImportIntoEDMV1Request: InscriptionImportIntoEDMV1Request; //

const { status, data } = await apiInstance.inscriptionImportIntoEDMV1(
    pkiInscriptionID,
    inscriptionImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **inscriptionImportIntoEDMV1Request** | **InscriptionImportIntoEDMV1Request**|  | |
| **pkiInscriptionID** | [**number**] |  | defaults to undefined|


### Return type

**InscriptionImportIntoEDMV1Response**

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

# **inscriptionPrepareFilesTransferV1**
> InscriptionPrepareFilesTransferV1Response inscriptionPrepareFilesTransferV1(inscriptionPrepareFilesTransferV1Request)



### Example

```typescript
import {
    ObjectInscriptionApi,
    Configuration,
    InscriptionPrepareFilesTransferV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInscriptionApi(configuration);

let pkiInscriptionID: number; // (default to undefined)
let inscriptionPrepareFilesTransferV1Request: InscriptionPrepareFilesTransferV1Request; //

const { status, data } = await apiInstance.inscriptionPrepareFilesTransferV1(
    pkiInscriptionID,
    inscriptionPrepareFilesTransferV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **inscriptionPrepareFilesTransferV1Request** | **InscriptionPrepareFilesTransferV1Request**|  | |
| **pkiInscriptionID** | [**number**] |  | defaults to undefined|


### Return type

**InscriptionPrepareFilesTransferV1Response**

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

