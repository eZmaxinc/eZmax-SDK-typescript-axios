# ObjectNotaryApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**notaryBatchDownloadV1**](#notarybatchdownloadv1) | **POST** /1/object/notary/{pkiNotaryID}/batchDownload | Download multiples attachments from a Notary|
|[**notaryGetAttachmentsV1**](#notarygetattachmentsv1) | **GET** /1/object/notary/{pkiNotaryID}/getAttachments | Retrieve Notary\&#39;s attachments|
|[**notaryGetCommunicationCountV1**](#notarygetcommunicationcountv1) | **GET** /1/object/notary/{pkiNotaryID}/getCommunicationCount | Retrieve Communication count|
|[**notaryGetCommunicationListV1**](#notarygetcommunicationlistv1) | **GET** /1/object/notary/{pkiNotaryID}/getCommunicationList | Retrieve Communication list|
|[**notaryGetCommunicationrecipientsV1**](#notarygetcommunicationrecipientsv1) | **GET** /1/object/notary/{pkiNotaryID}/getCommunicationrecipients | Retrieve Communication recipients|
|[**notaryGetCommunicationsendersV1**](#notarygetcommunicationsendersv1) | **GET** /1/object/notary/{pkiNotaryID}/getCommunicationsenders | Retrieve Communication senders|
|[**notaryGetDocumenttypechecklistV1**](#notarygetdocumenttypechecklistv1) | **GET** /1/object/notary/{pkiNotaryID}/getDocumenttypechecklist | Retrieve Document type checklist|
|[**notaryGetListV1**](#notarygetlistv1) | **GET** /1/object/notary/getList | Retrieve Notary list|
|[**notaryImportIntoEDMV1**](#notaryimportintoedmv1) | **POST** /1/object/notary/{pkiNotaryID}/importIntoEDM | Import attachments into the Notary|
|[**notarySyncDocumenttypechecklistV1**](#notarysyncdocumenttypechecklistv1) | **POST** /1/object/notary/{pkiNotaryID}/syncDocumenttypechecklist | Synchronize Document type checklist|

# **notaryBatchDownloadV1**
> File notaryBatchDownloadV1(notaryBatchDownloadV1Request)


### Example

```typescript
import {
    ObjectNotaryApi,
    Configuration,
    NotaryBatchDownloadV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectNotaryApi(configuration);

let pkiNotaryID: number; // (default to undefined)
let notaryBatchDownloadV1Request: NotaryBatchDownloadV1Request; //

const { status, data } = await apiInstance.notaryBatchDownloadV1(
    pkiNotaryID,
    notaryBatchDownloadV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **notaryBatchDownloadV1Request** | **NotaryBatchDownloadV1Request**|  | |
| **pkiNotaryID** | [**number**] |  | defaults to undefined|


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

# **notaryGetAttachmentsV1**
> NotaryGetAttachmentsV1Response notaryGetAttachmentsV1()


### Example

```typescript
import {
    ObjectNotaryApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectNotaryApi(configuration);

let pkiNotaryID: number; // (default to undefined)

const { status, data } = await apiInstance.notaryGetAttachmentsV1(
    pkiNotaryID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiNotaryID** | [**number**] |  | defaults to undefined|


### Return type

**NotaryGetAttachmentsV1Response**

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

# **notaryGetCommunicationCountV1**
> NotaryGetCommunicationCountV1Response notaryGetCommunicationCountV1()


### Example

```typescript
import {
    ObjectNotaryApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectNotaryApi(configuration);

let pkiNotaryID: number; // (default to undefined)

const { status, data } = await apiInstance.notaryGetCommunicationCountV1(
    pkiNotaryID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiNotaryID** | [**number**] |  | defaults to undefined|


### Return type

**NotaryGetCommunicationCountV1Response**

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

# **notaryGetCommunicationListV1**
> NotaryGetCommunicationListV1Response notaryGetCommunicationListV1()


### Example

```typescript
import {
    ObjectNotaryApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectNotaryApi(configuration);

let pkiNotaryID: number; // (default to undefined)

const { status, data } = await apiInstance.notaryGetCommunicationListV1(
    pkiNotaryID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiNotaryID** | [**number**] |  | defaults to undefined|


### Return type

**NotaryGetCommunicationListV1Response**

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

# **notaryGetCommunicationrecipientsV1**
> NotaryGetCommunicationrecipientsV1Response notaryGetCommunicationrecipientsV1()


### Example

```typescript
import {
    ObjectNotaryApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectNotaryApi(configuration);

let pkiNotaryID: number; // (default to undefined)

const { status, data } = await apiInstance.notaryGetCommunicationrecipientsV1(
    pkiNotaryID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiNotaryID** | [**number**] |  | defaults to undefined|


### Return type

**NotaryGetCommunicationrecipientsV1Response**

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

# **notaryGetCommunicationsendersV1**
> NotaryGetCommunicationsendersV1Response notaryGetCommunicationsendersV1()


### Example

```typescript
import {
    ObjectNotaryApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectNotaryApi(configuration);

let pkiNotaryID: number; // (default to undefined)

const { status, data } = await apiInstance.notaryGetCommunicationsendersV1(
    pkiNotaryID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiNotaryID** | [**number**] |  | defaults to undefined|


### Return type

**NotaryGetCommunicationsendersV1Response**

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

# **notaryGetDocumenttypechecklistV1**
> NotaryGetDocumenttypechecklistV1Response notaryGetDocumenttypechecklistV1()


### Example

```typescript
import {
    ObjectNotaryApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectNotaryApi(configuration);

let pkiNotaryID: number; // (default to undefined)

const { status, data } = await apiInstance.notaryGetDocumenttypechecklistV1(
    pkiNotaryID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiNotaryID** | [**number**] |  | defaults to undefined|


### Return type

**NotaryGetDocumenttypechecklistV1Response**

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

# **notaryGetListV1**
> NotaryGetListV1Response notaryGetListV1()



### Example

```typescript
import {
    ObjectNotaryApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectNotaryApi(configuration);

let eOrderBy: 'pkiNotaryID_ASC' | 'pkiNotaryID_DESC' | 'fkiPaymentmethodID_ASC' | 'fkiPaymentmethodID_DESC' | 'fkiProvinceID_ASC' | 'fkiProvinceID_DESC' | 'fkiCountryID_ASC' | 'fkiCountryID_DESC' | 'sContactLastname_ASC' | 'sContactLastname_DESC' | 'sContactFirstname_ASC' | 'sContactFirstname_DESC' | 'sContactCompany_ASC' | 'sContactCompany_DESC' | 'sAddressCivic_ASC' | 'sAddressCivic_DESC' | 'sAddressStreet_ASC' | 'sAddressStreet_DESC' | 'sAddressSuite_ASC' | 'sAddressSuite_DESC' | 'sAddressCity_ASC' | 'sAddressCity_DESC' | 'sPhoneE164_ASC' | 'sPhoneE164_DESC' | 'sPaymentmethodDescriptionX_ASC' | 'sPaymentmethodDescriptionX_DESC' | 'sProvinceNameX_ASC' | 'sProvinceNameX_DESC' | 'sCountryNameX_ASC' | 'sCountryNameX_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.notaryGetListV1(
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
| **eOrderBy** | [**&#39;pkiNotaryID_ASC&#39; | &#39;pkiNotaryID_DESC&#39; | &#39;fkiPaymentmethodID_ASC&#39; | &#39;fkiPaymentmethodID_DESC&#39; | &#39;fkiProvinceID_ASC&#39; | &#39;fkiProvinceID_DESC&#39; | &#39;fkiCountryID_ASC&#39; | &#39;fkiCountryID_DESC&#39; | &#39;sContactLastname_ASC&#39; | &#39;sContactLastname_DESC&#39; | &#39;sContactFirstname_ASC&#39; | &#39;sContactFirstname_DESC&#39; | &#39;sContactCompany_ASC&#39; | &#39;sContactCompany_DESC&#39; | &#39;sAddressCivic_ASC&#39; | &#39;sAddressCivic_DESC&#39; | &#39;sAddressStreet_ASC&#39; | &#39;sAddressStreet_DESC&#39; | &#39;sAddressSuite_ASC&#39; | &#39;sAddressSuite_DESC&#39; | &#39;sAddressCity_ASC&#39; | &#39;sAddressCity_DESC&#39; | &#39;sPhoneE164_ASC&#39; | &#39;sPhoneE164_DESC&#39; | &#39;sPaymentmethodDescriptionX_ASC&#39; | &#39;sPaymentmethodDescriptionX_DESC&#39; | &#39;sProvinceNameX_ASC&#39; | &#39;sProvinceNameX_DESC&#39; | &#39;sCountryNameX_ASC&#39; | &#39;sCountryNameX_DESC&#39;**]**Array<&#39;pkiNotaryID_ASC&#39; &#124; &#39;pkiNotaryID_DESC&#39; &#124; &#39;fkiPaymentmethodID_ASC&#39; &#124; &#39;fkiPaymentmethodID_DESC&#39; &#124; &#39;fkiProvinceID_ASC&#39; &#124; &#39;fkiProvinceID_DESC&#39; &#124; &#39;fkiCountryID_ASC&#39; &#124; &#39;fkiCountryID_DESC&#39; &#124; &#39;sContactLastname_ASC&#39; &#124; &#39;sContactLastname_DESC&#39; &#124; &#39;sContactFirstname_ASC&#39; &#124; &#39;sContactFirstname_DESC&#39; &#124; &#39;sContactCompany_ASC&#39; &#124; &#39;sContactCompany_DESC&#39; &#124; &#39;sAddressCivic_ASC&#39; &#124; &#39;sAddressCivic_DESC&#39; &#124; &#39;sAddressStreet_ASC&#39; &#124; &#39;sAddressStreet_DESC&#39; &#124; &#39;sAddressSuite_ASC&#39; &#124; &#39;sAddressSuite_DESC&#39; &#124; &#39;sAddressCity_ASC&#39; &#124; &#39;sAddressCity_DESC&#39; &#124; &#39;sPhoneE164_ASC&#39; &#124; &#39;sPhoneE164_DESC&#39; &#124; &#39;sPaymentmethodDescriptionX_ASC&#39; &#124; &#39;sPaymentmethodDescriptionX_DESC&#39; &#124; &#39;sProvinceNameX_ASC&#39; &#124; &#39;sProvinceNameX_DESC&#39; &#124; &#39;sCountryNameX_ASC&#39; &#124; &#39;sCountryNameX_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**NotaryGetListV1Response**

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

# **notaryImportIntoEDMV1**
> NotaryImportIntoEDMV1Response notaryImportIntoEDMV1(notaryImportIntoEDMV1Request)


### Example

```typescript
import {
    ObjectNotaryApi,
    Configuration,
    NotaryImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectNotaryApi(configuration);

let pkiNotaryID: number; // (default to undefined)
let notaryImportIntoEDMV1Request: NotaryImportIntoEDMV1Request; //

const { status, data } = await apiInstance.notaryImportIntoEDMV1(
    pkiNotaryID,
    notaryImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **notaryImportIntoEDMV1Request** | **NotaryImportIntoEDMV1Request**|  | |
| **pkiNotaryID** | [**number**] |  | defaults to undefined|


### Return type

**NotaryImportIntoEDMV1Response**

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

# **notarySyncDocumenttypechecklistV1**
> NotarySyncDocumenttypechecklistV1Response notarySyncDocumenttypechecklistV1()


### Example

```typescript
import {
    ObjectNotaryApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectNotaryApi(configuration);

let pkiNotaryID: number; // (default to undefined)
let body: object; // (optional)

const { status, data } = await apiInstance.notarySyncDocumenttypechecklistV1(
    pkiNotaryID,
    body
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **body** | **object**|  | |
| **pkiNotaryID** | [**number**] |  | defaults to undefined|


### Return type

**NotarySyncDocumenttypechecklistV1Response**

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

