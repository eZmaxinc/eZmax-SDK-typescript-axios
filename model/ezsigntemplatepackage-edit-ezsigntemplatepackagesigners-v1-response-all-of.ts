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
import { EzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseMPayload } from './ezsigntemplatepackage-edit-ezsigntemplatepackagesigners-v1-response-mpayload';

/**
 * 
 * @export
 * @interface EzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseAllOf
 */
export interface EzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseAllOf {
    /**
     * 
     * @type {EzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseMPayload}
     * @memberof EzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseAllOf
     */
    'mPayload': EzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseAllOf
 */
export class DataObjectEzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseAllOf {
   mPayload:EzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseMPayload = new DataObjectEzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseAllOf Validation Object
 * @class ValidationObjectEzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseAllOf
 */
export class ValidationObjectEzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseAllOf {
   mPayload = new ValidationObjectEzsigntemplatepackageEditEzsigntemplatepackagesignersV1ResponseMPayload()
} 


