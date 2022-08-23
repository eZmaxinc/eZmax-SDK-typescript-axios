/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.10
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * Generic Error Message
 * @export
 * @interface CommonResponseError
 */
export interface CommonResponseError {
    /**
     * More detail about the error
     * @type {string}
     * @memberof CommonResponseError
     */
    'sErrorMessage': string;
    /**
     * The error code. See documentation for valid values
     * @type {string}
     * @memberof CommonResponseError
     */
    'eErrorCode': string;
}

