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
import type { EzsignbulksendRequestCompound } from './ezsignbulksend-request-compound';

/**
 * Request for PUT /1/object/ezsignbulksend/{pkiEzsignbulksendID}
 * @export
 * @interface EzsignbulksendEditObjectV1Request
 */
export interface EzsignbulksendEditObjectV1Request {
    /**
     * 
     * @type {EzsignbulksendRequestCompound}
     * @memberof EzsignbulksendEditObjectV1Request
     */
    /*'objEzsignbulksend': EzsignbulksendRequestCompound;*/
    'objEzsignbulksend': EzsignbulksendRequestCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignbulksendRequestCompound } from './'
// @ts-ignore
import { ValidationObjectEzsignbulksendRequestCompound } from './'

/**
 * @export 
 * A EzsignbulksendEditObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendEditObjectV1Request
 */
export class DataObjectEzsignbulksendEditObjectV1Request {
   objEzsignbulksend:EzsignbulksendRequestCompound = new DataObjectEzsignbulksendRequestCompound()
}

/**
 * @export 
 * A EzsignbulksendEditObjectV1Request Validation Object
 * @class ValidationObjectEzsignbulksendEditObjectV1Request
 */
export class ValidationObjectEzsignbulksendEditObjectV1Request {
   objEzsignbulksend = new ValidationObjectEzsignbulksendRequestCompound()
} 


