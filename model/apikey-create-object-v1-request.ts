/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.0.47
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { ApikeyRequest } from './apikey-request';
import { ApikeyRequestCompound } from './apikey-request-compound';



/**
 * Request for the /1/object/apikey/createObject API Request
 * @export
 * @interface ApikeyCreateObjectV1Request
 */
export interface ApikeyCreateObjectV1Request {
    /**
     * 
     * @type {ApikeyRequest}
     * @memberof ApikeyCreateObjectV1Request
     */
    objApikey?: ApikeyRequest;
    /**
     * 
     * @type {ApikeyRequestCompound}
     * @memberof ApikeyCreateObjectV1Request
     */
    objApikeyCompound?: ApikeyRequestCompound;
}
