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
import { EzsigntemplatedocumentRequestCompound } from './ezsigntemplatedocument-request-compound';

/**
 * Request for PUT /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}
 * @export
 * @interface EzsigntemplatedocumentEditObjectV1Request
 */
export interface EzsigntemplatedocumentEditObjectV1Request {
    /**
     * 
     * @type {EzsigntemplatedocumentRequestCompound}
     * @memberof EzsigntemplatedocumentEditObjectV1Request
     */
    'objEzsigntemplatedocument': EzsigntemplatedocumentRequestCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplatedocumentRequestCompound } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatedocumentRequestCompound } from './'

/**
 * @export 
 * A EzsigntemplatedocumentEditObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatedocumentEditObjectV1Request
 */
export class DataObjectEzsigntemplatedocumentEditObjectV1Request {
   objEzsigntemplatedocument:EzsigntemplatedocumentRequestCompound = new DataObjectEzsigntemplatedocumentRequestCompound()
}

/**
 * @export 
 * A EzsigntemplatedocumentEditObjectV1Request Validation Object
 * @class ValidationObjectEzsigntemplatedocumentEditObjectV1Request
 */
export class ValidationObjectEzsigntemplatedocumentEditObjectV1Request {
   objEzsigntemplatedocument = new ValidationObjectEzsigntemplatedocumentRequestCompound()
} 


