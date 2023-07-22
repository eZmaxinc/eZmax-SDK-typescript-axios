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
import { EzsigntemplatesignerGetObjectV2ResponseMPayload } from './ezsigntemplatesigner-get-object-v2-response-mpayload';

/**
 * 
 * @export
 * @interface EzsigntemplatesignerGetObjectV2ResponseAllOf
 */
export interface EzsigntemplatesignerGetObjectV2ResponseAllOf {
    /**
     * 
     * @type {EzsigntemplatesignerGetObjectV2ResponseMPayload}
     * @memberof EzsigntemplatesignerGetObjectV2ResponseAllOf
     */
    'mPayload': EzsigntemplatesignerGetObjectV2ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplatesignerGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatesignerGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplatesignerGetObjectV2ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatesignerGetObjectV2ResponseAllOf
 */
export class DataObjectEzsigntemplatesignerGetObjectV2ResponseAllOf {
   mPayload:EzsigntemplatesignerGetObjectV2ResponseMPayload = new DataObjectEzsigntemplatesignerGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplatesignerGetObjectV2ResponseAllOf Validation Object
 * @class ValidationObjectEzsigntemplatesignerGetObjectV2ResponseAllOf
 */
export class ValidationObjectEzsigntemplatesignerGetObjectV2ResponseAllOf {
   mPayload = new ValidationObjectEzsigntemplatesignerGetObjectV2ResponseMPayload()
} 


