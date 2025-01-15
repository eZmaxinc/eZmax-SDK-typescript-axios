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
import type { SystemconfigurationRequestCompound } from './systemconfiguration-request-compound';

/**
 * Request for PUT /1/object/systemconfiguration/{pkiSystemconfigurationID}
 * @export
 * @interface SystemconfigurationEditObjectV1Request
 */
export interface SystemconfigurationEditObjectV1Request {
    /**
     * 
     * @type {SystemconfigurationRequestCompound}
     * @memberof SystemconfigurationEditObjectV1Request
     */
    /*'objSystemconfiguration': SystemconfigurationRequestCompound;*/
    'objSystemconfiguration': SystemconfigurationRequestCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectSystemconfigurationRequestCompound } from './'
// @ts-ignore
import { ValidationObjectSystemconfigurationRequestCompound } from './'

/**
 * @export 
 * A SystemconfigurationEditObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectSystemconfigurationEditObjectV1Request
 */
export class DataObjectSystemconfigurationEditObjectV1Request {
   objSystemconfiguration:SystemconfigurationRequestCompound = new DataObjectSystemconfigurationRequestCompound()
}

/**
 * @export 
 * A SystemconfigurationEditObjectV1Request Validation Object
 * @class ValidationObjectSystemconfigurationEditObjectV1Request
 */
export class ValidationObjectSystemconfigurationEditObjectV1Request {
   objSystemconfiguration = new ValidationObjectSystemconfigurationRequestCompound()
} 


