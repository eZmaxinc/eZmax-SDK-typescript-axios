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
import { EzsigntemplateformfieldgroupCreateObjectV1ResponseMPayload } from './ezsigntemplateformfieldgroup-create-object-v1-response-mpayload';

/**
 * 
 * @export
 * @interface EzsigntemplateformfieldgroupCreateObjectV1ResponseAllOf
 */
export interface EzsigntemplateformfieldgroupCreateObjectV1ResponseAllOf {
    /**
     * 
     * @type {EzsigntemplateformfieldgroupCreateObjectV1ResponseMPayload}
     * @memberof EzsigntemplateformfieldgroupCreateObjectV1ResponseAllOf
     */
    'mPayload': EzsigntemplateformfieldgroupCreateObjectV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplateformfieldgroupCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplateformfieldgroupCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplateformfieldgroupCreateObjectV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateformfieldgroupCreateObjectV1ResponseAllOf
 */
export class DataObjectEzsigntemplateformfieldgroupCreateObjectV1ResponseAllOf {
   mPayload:EzsigntemplateformfieldgroupCreateObjectV1ResponseMPayload = new DataObjectEzsigntemplateformfieldgroupCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplateformfieldgroupCreateObjectV1ResponseAllOf Validation Object
 * @class ValidationObjectEzsigntemplateformfieldgroupCreateObjectV1ResponseAllOf
 */
export class ValidationObjectEzsigntemplateformfieldgroupCreateObjectV1ResponseAllOf {
   mPayload = new ValidationObjectEzsigntemplateformfieldgroupCreateObjectV1ResponseMPayload()
} 


