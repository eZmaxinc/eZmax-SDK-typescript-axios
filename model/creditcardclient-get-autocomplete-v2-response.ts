/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import type { CreditcardclientGetAutocompleteV2ResponseMPayload } from './creditcardclient-get-autocomplete-v2-response-mpayload';

/**
 * @type CreditcardclientGetAutocompleteV2Response
 * Response for GET /2/object/creditcardclient/getAutocomplete
 * @export
 */
/*export type CreditcardclientGetAutocompleteV2Response = CommonResponse;*/
export interface CreditcardclientGetAutocompleteV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof CreditcardclientGetAutocompleteV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof CreditcardclientGetAutocompleteV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {CreditcardclientGetAutocompleteV2ResponseMPayload}
     * @memberof CreditcardclientGetAutocompleteV2Response
     */
    mPayload:CreditcardclientGetAutocompleteV2ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { DataObjectCreditcardclientGetAutocompleteV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectCreditcardclientGetAutocompleteV2ResponseMPayload } from './'

/**
 * @export 
 * A CreditcardclientGetAutocompleteV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCreditcardclientGetAutocompleteV2Response
 */
export class DataObjectCreditcardclientGetAutocompleteV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:CreditcardclientGetAutocompleteV2ResponseMPayload = new DataObjectCreditcardclientGetAutocompleteV2ResponseMPayload()
}

/**
 * @export 
 * A CreditcardclientGetAutocompleteV2Response Validation Object
 * @class ValidationObjectCreditcardclientGetAutocompleteV2Response
 */
export class ValidationObjectCreditcardclientGetAutocompleteV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectCreditcardclientGetAutocompleteV2ResponseMPayload()
} 


