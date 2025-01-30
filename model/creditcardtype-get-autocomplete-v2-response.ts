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
import type { CreditcardtypeGetAutocompleteV2ResponseMPayload } from './creditcardtype-get-autocomplete-v2-response-mpayload';

/**
 * @type CreditcardtypeGetAutocompleteV2Response
 * Response for GET /2/object/creditcardtype/getAutocomplete
 * @export
 */
/*export type CreditcardtypeGetAutocompleteV2Response = CommonResponse;*/
export interface CreditcardtypeGetAutocompleteV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof CreditcardtypeGetAutocompleteV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof CreditcardtypeGetAutocompleteV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {CreditcardtypeGetAutocompleteV2ResponseMPayload}
     * @memberof CreditcardtypeGetAutocompleteV2Response
     */
    mPayload:CreditcardtypeGetAutocompleteV2ResponseMPayload 
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
import { DataObjectCreditcardtypeGetAutocompleteV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectCreditcardtypeGetAutocompleteV2ResponseMPayload } from './'

/**
 * @export 
 * A CreditcardtypeGetAutocompleteV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCreditcardtypeGetAutocompleteV2Response
 */
export class DataObjectCreditcardtypeGetAutocompleteV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:CreditcardtypeGetAutocompleteV2ResponseMPayload = new DataObjectCreditcardtypeGetAutocompleteV2ResponseMPayload()
}

/**
 * @export 
 * A CreditcardtypeGetAutocompleteV2Response Validation Object
 * @class ValidationObjectCreditcardtypeGetAutocompleteV2Response
 */
export class ValidationObjectCreditcardtypeGetAutocompleteV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectCreditcardtypeGetAutocompleteV2ResponseMPayload()
} 


