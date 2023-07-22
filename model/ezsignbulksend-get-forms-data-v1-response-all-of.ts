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
import { EzsignbulksendGetFormsDataV1ResponseMPayload } from './ezsignbulksend-get-forms-data-v1-response-mpayload';

/**
 * 
 * @export
 * @interface EzsignbulksendGetFormsDataV1ResponseAllOf
 */
export interface EzsignbulksendGetFormsDataV1ResponseAllOf {
    /**
     * 
     * @type {EzsignbulksendGetFormsDataV1ResponseMPayload}
     * @memberof EzsignbulksendGetFormsDataV1ResponseAllOf
     */
    'mPayload': EzsignbulksendGetFormsDataV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignbulksendGetFormsDataV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsignbulksendGetFormsDataV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignbulksendGetFormsDataV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendGetFormsDataV1ResponseAllOf
 */
export class DataObjectEzsignbulksendGetFormsDataV1ResponseAllOf {
   mPayload:EzsignbulksendGetFormsDataV1ResponseMPayload = new DataObjectEzsignbulksendGetFormsDataV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignbulksendGetFormsDataV1ResponseAllOf Validation Object
 * @class ValidationObjectEzsignbulksendGetFormsDataV1ResponseAllOf
 */
export class ValidationObjectEzsignbulksendGetFormsDataV1ResponseAllOf {
   mPayload = new ValidationObjectEzsignbulksendGetFormsDataV1ResponseMPayload()
} 


