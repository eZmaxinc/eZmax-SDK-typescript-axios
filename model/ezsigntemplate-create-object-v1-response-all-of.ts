/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateCreateObjectV1ResponseMPayload } from './ezsigntemplate-create-object-v1-response-mpayload';

/**
 * 
 * @export
 * @interface EzsigntemplateCreateObjectV1ResponseAllOf
 */
export interface EzsigntemplateCreateObjectV1ResponseAllOf {
    /**
     * 
     * @type {EzsigntemplateCreateObjectV1ResponseMPayload}
     * @memberof EzsigntemplateCreateObjectV1ResponseAllOf
     */
    'mPayload': EzsigntemplateCreateObjectV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplateCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplateCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplateCreateObjectV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateCreateObjectV1ResponseAllOf
 */
export class DataObjectEzsigntemplateCreateObjectV1ResponseAllOf {
   mPayload:EzsigntemplateCreateObjectV1ResponseMPayload = new DataObjectEzsigntemplateCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplateCreateObjectV1ResponseAllOf Validation Object
 * @class ValidationObjectEzsigntemplateCreateObjectV1ResponseAllOf
 */
export class ValidationObjectEzsigntemplateCreateObjectV1ResponseAllOf {
   mPayload = new ValidationObjectEzsigntemplateCreateObjectV1ResponseMPayload()
} 


