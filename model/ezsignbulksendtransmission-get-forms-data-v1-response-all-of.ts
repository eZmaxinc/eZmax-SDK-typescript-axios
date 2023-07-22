/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksendtransmissionGetFormsDataV1ResponseMPayload } from './ezsignbulksendtransmission-get-forms-data-v1-response-mpayload';

/**
 * 
 * @export
 * @interface EzsignbulksendtransmissionGetFormsDataV1ResponseAllOf
 */
export interface EzsignbulksendtransmissionGetFormsDataV1ResponseAllOf {
    /**
     * 
     * @type {EzsignbulksendtransmissionGetFormsDataV1ResponseMPayload}
     * @memberof EzsignbulksendtransmissionGetFormsDataV1ResponseAllOf
     */
    'mPayload': EzsignbulksendtransmissionGetFormsDataV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignbulksendtransmissionGetFormsDataV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsignbulksendtransmissionGetFormsDataV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignbulksendtransmissionGetFormsDataV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendtransmissionGetFormsDataV1ResponseAllOf
 */
export class DataObjectEzsignbulksendtransmissionGetFormsDataV1ResponseAllOf {
   mPayload:EzsignbulksendtransmissionGetFormsDataV1ResponseMPayload = new DataObjectEzsignbulksendtransmissionGetFormsDataV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignbulksendtransmissionGetFormsDataV1ResponseAllOf Validation Object
 * @class ValidationObjectEzsignbulksendtransmissionGetFormsDataV1ResponseAllOf
 */
export class ValidationObjectEzsignbulksendtransmissionGetFormsDataV1ResponseAllOf {
   mPayload = new ValidationObjectEzsignbulksendtransmissionGetFormsDataV1ResponseMPayload()
} 


