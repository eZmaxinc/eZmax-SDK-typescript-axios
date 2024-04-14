/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackageResponseCompound } from './ezsigntemplatepackage-response-compound';

/**
 * Payload for GET /2/object/ezsigntemplatepackage/{pkiEzsigntemplatepackageID}
 * @export
 * @interface EzsigntemplatepackageGetObjectV2ResponseMPayload
 */
export interface EzsigntemplatepackageGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {EzsigntemplatepackageResponseCompound}
     * @memberof EzsigntemplatepackageGetObjectV2ResponseMPayload
     */
    /*'objEzsigntemplatepackage': EzsigntemplatepackageResponseCompound;*/
    'objEzsigntemplatepackage': EzsigntemplatepackageResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplatepackageResponseCompound } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatepackageResponseCompound } from './'

/**
 * @export 
 * A EzsigntemplatepackageGetObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackageGetObjectV2ResponseMPayload
 */
export class DataObjectEzsigntemplatepackageGetObjectV2ResponseMPayload {
   objEzsigntemplatepackage:EzsigntemplatepackageResponseCompound = new DataObjectEzsigntemplatepackageResponseCompound()
}

/**
 * @export 
 * A EzsigntemplatepackageGetObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectEzsigntemplatepackageGetObjectV2ResponseMPayload
 */
export class ValidationObjectEzsigntemplatepackageGetObjectV2ResponseMPayload {
   objEzsigntemplatepackage = new ValidationObjectEzsigntemplatepackageResponseCompound()
} 


