/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatesignatureRequestCompound } from './ezsigntemplatesignature-request-compound';

/**
 * Request for PUT /1/object/ezsigntemplatesignature/{pkiEzsigntemplatesignatureID}
 * @export
 * @interface EzsigntemplatesignatureEditObjectV1Request
 */
export interface EzsigntemplatesignatureEditObjectV1Request {
    /**
     * 
     * @type {EzsigntemplatesignatureRequestCompound}
     * @memberof EzsigntemplatesignatureEditObjectV1Request
     */
    'objEzsigntemplatesignature': EzsigntemplatesignatureRequestCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplatesignatureRequestCompound } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatesignatureRequestCompound } from './'

/**
 * @export 
 * A EzsigntemplatesignatureEditObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatesignatureEditObjectV1Request
 */
export class DataObjectEzsigntemplatesignatureEditObjectV1Request {
   objEzsigntemplatesignature:EzsigntemplatesignatureRequestCompound = new DataObjectEzsigntemplatesignatureRequestCompound()
}

/**
 * @export 
 * A EzsigntemplatesignatureEditObjectV1Request Validation Object
 * @class ValidationObjectEzsigntemplatesignatureEditObjectV1Request
 */
export class ValidationObjectEzsigntemplatesignatureEditObjectV1Request {
   objEzsigntemplatesignature = new ValidationObjectEzsigntemplatesignatureRequestCompound()
} 


