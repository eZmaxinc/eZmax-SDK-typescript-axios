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
import { EzsigntemplateformfieldgroupRequestCompound } from './ezsigntemplateformfieldgroup-request-compound';

/**
 * Request for PUT /1/object/ezsigntemplateformfieldgroup/{pkiEzsigntemplateformfieldgroupID}
 * @export
 * @interface EzsigntemplateformfieldgroupEditObjectV1Request
 */
export interface EzsigntemplateformfieldgroupEditObjectV1Request {
    /**
     * 
     * @type {EzsigntemplateformfieldgroupRequestCompound}
     * @memberof EzsigntemplateformfieldgroupEditObjectV1Request
     */
    'objEzsigntemplateformfieldgroup': EzsigntemplateformfieldgroupRequestCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplateformfieldgroupRequestCompound } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplateformfieldgroupRequestCompound } from './'

/**
 * @export 
 * A EzsigntemplateformfieldgroupEditObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateformfieldgroupEditObjectV1Request
 */
export class DataObjectEzsigntemplateformfieldgroupEditObjectV1Request {
   objEzsigntemplateformfieldgroup:EzsigntemplateformfieldgroupRequestCompound = new DataObjectEzsigntemplateformfieldgroupRequestCompound()
}

/**
 * @export 
 * A EzsigntemplateformfieldgroupEditObjectV1Request Validation Object
 * @class ValidationObjectEzsigntemplateformfieldgroupEditObjectV1Request
 */
export class ValidationObjectEzsigntemplateformfieldgroupEditObjectV1Request {
   objEzsigntemplateformfieldgroup = new ValidationObjectEzsigntemplateformfieldgroupRequestCompound()
} 


