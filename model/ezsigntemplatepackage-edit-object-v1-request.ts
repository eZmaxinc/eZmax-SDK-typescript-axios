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
import type { EzsigntemplatepackageRequestCompound } from './ezsigntemplatepackage-request-compound';

/**
 * Request for PUT /1/object/ezsigntemplatepackage/{pkiEzsigntemplatepackageID}
 * @export
 * @interface EzsigntemplatepackageEditObjectV1Request
 */
export interface EzsigntemplatepackageEditObjectV1Request {
    /**
     * 
     * @type {EzsigntemplatepackageRequestCompound}
     * @memberof EzsigntemplatepackageEditObjectV1Request
     */
    /*'objEzsigntemplatepackage': EzsigntemplatepackageRequestCompound;*/
    'objEzsigntemplatepackage': EzsigntemplatepackageRequestCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplatepackageRequestCompound } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatepackageRequestCompound } from './'

/**
 * @export 
 * A EzsigntemplatepackageEditObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackageEditObjectV1Request
 */
export class DataObjectEzsigntemplatepackageEditObjectV1Request {
   objEzsigntemplatepackage:EzsigntemplatepackageRequestCompound = new DataObjectEzsigntemplatepackageRequestCompound()
}

/**
 * @export 
 * A EzsigntemplatepackageEditObjectV1Request Validation Object
 * @class ValidationObjectEzsigntemplatepackageEditObjectV1Request
 */
export class ValidationObjectEzsigntemplatepackageEditObjectV1Request {
   objEzsigntemplatepackage = new ValidationObjectEzsigntemplatepackageRequestCompound()
} 


