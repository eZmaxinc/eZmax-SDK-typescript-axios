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
import { EzsigntemplateRequestCompound } from './ezsigntemplate-request-compound';

/**
 * Request for PUT /1/object/ezsigntemplate/{pkiEzsigntemplateID}
 * @export
 * @interface EzsigntemplateEditObjectV1Request
 */
export interface EzsigntemplateEditObjectV1Request {
    /**
     * 
     * @type {EzsigntemplateRequestCompound}
     * @memberof EzsigntemplateEditObjectV1Request
     */
    /*'objEzsigntemplate': EzsigntemplateRequestCompound;*/
    'objEzsigntemplate': EzsigntemplateRequestCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplateRequestCompound } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplateRequestCompound } from './'

/**
 * @export 
 * A EzsigntemplateEditObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateEditObjectV1Request
 */
export class DataObjectEzsigntemplateEditObjectV1Request {
   objEzsigntemplate:EzsigntemplateRequestCompound = new DataObjectEzsigntemplateRequestCompound()
}

/**
 * @export 
 * A EzsigntemplateEditObjectV1Request Validation Object
 * @class ValidationObjectEzsigntemplateEditObjectV1Request
 */
export class ValidationObjectEzsigntemplateEditObjectV1Request {
   objEzsigntemplate = new ValidationObjectEzsigntemplateRequestCompound()
} 


