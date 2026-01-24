# ObjectTranqcontractApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**tranqcontractGetCommunicationCountV1**](#tranqcontractgetcommunicationcountv1) | **GET** /1/object/tranqcontract/{pkiTranqcontractID}/getCommunicationCount | Retrieve Communication count|
|[**tranqcontractGetCommunicationListV1**](#tranqcontractgetcommunicationlistv1) | **GET** /1/object/tranqcontract/{pkiTranqcontractID}/getCommunicationList | Retrieve Communication list|
|[**tranqcontractGetCommunicationrecipientsV1**](#tranqcontractgetcommunicationrecipientsv1) | **GET** /1/object/tranqcontract/{pkiTranqcontractID}/getCommunicationrecipients | Retrieve Tranqcontract\&#39;s Communicationrecipient|
|[**tranqcontractGetCommunicationsendersV1**](#tranqcontractgetcommunicationsendersv1) | **GET** /1/object/tranqcontract/{pkiTranqcontractID}/getCommunicationsenders | Retrieve Tranqcontract\&#39;s Communicationsender|
|[**tranqcontractImportIntoEDMV1**](#tranqcontractimportintoedmv1) | **POST** /1/object/tranqcontract/{pkiTranqcontractID}/importIntoEDM | Import attachments into the Tranqcontract|

# **tranqcontractGetCommunicationCountV1**
> TranqcontractGetCommunicationCountV1Response tranqcontractGetCommunicationCountV1()



### Example

```typescript
import {
    ObjectTranqcontractApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectTranqcontractApi(configuration);

let pkiTranqcontractID: number; // (default to undefined)

const { status, data } = await apiInstance.tranqcontractGetCommunicationCountV1(
    pkiTranqcontractID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiTranqcontractID** | [**number**] |  | defaults to undefined|


### Return type

**TranqcontractGetCommunicationCountV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **tranqcontractGetCommunicationListV1**
> TranqcontractGetCommunicationListV1Response tranqcontractGetCommunicationListV1()



### Example

```typescript
import {
    ObjectTranqcontractApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectTranqcontractApi(configuration);

let pkiTranqcontractID: number; // (default to undefined)

const { status, data } = await apiInstance.tranqcontractGetCommunicationListV1(
    pkiTranqcontractID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiTranqcontractID** | [**number**] |  | defaults to undefined|


### Return type

**TranqcontractGetCommunicationListV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **tranqcontractGetCommunicationrecipientsV1**
> TranqcontractGetCommunicationrecipientsV1Response tranqcontractGetCommunicationrecipientsV1()



### Example

```typescript
import {
    ObjectTranqcontractApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectTranqcontractApi(configuration);

let pkiTranqcontractID: number; // (default to undefined)

const { status, data } = await apiInstance.tranqcontractGetCommunicationrecipientsV1(
    pkiTranqcontractID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiTranqcontractID** | [**number**] |  | defaults to undefined|


### Return type

**TranqcontractGetCommunicationrecipientsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **tranqcontractGetCommunicationsendersV1**
> TranqcontractGetCommunicationsendersV1Response tranqcontractGetCommunicationsendersV1()



### Example

```typescript
import {
    ObjectTranqcontractApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectTranqcontractApi(configuration);

let pkiTranqcontractID: number; // (default to undefined)

const { status, data } = await apiInstance.tranqcontractGetCommunicationsendersV1(
    pkiTranqcontractID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiTranqcontractID** | [**number**] |  | defaults to undefined|


### Return type

**TranqcontractGetCommunicationsendersV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **tranqcontractImportIntoEDMV1**
> TranqcontractImportIntoEDMV1Response tranqcontractImportIntoEDMV1(tranqcontractImportIntoEDMV1Request)



### Example

```typescript
import {
    ObjectTranqcontractApi,
    Configuration,
    TranqcontractImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectTranqcontractApi(configuration);

let pkiTranqcontractID: number; // (default to undefined)
let tranqcontractImportIntoEDMV1Request: TranqcontractImportIntoEDMV1Request; //

const { status, data } = await apiInstance.tranqcontractImportIntoEDMV1(
    pkiTranqcontractID,
    tranqcontractImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **tranqcontractImportIntoEDMV1Request** | **TranqcontractImportIntoEDMV1Request**|  | |
| **pkiTranqcontractID** | [**number**] |  | defaults to undefined|


### Return type

**TranqcontractImportIntoEDMV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

