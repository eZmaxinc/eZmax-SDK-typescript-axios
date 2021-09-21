/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.0.48
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */





/**
 * This is a debug object containing debugging information on the actual function
 * @export
 * @interface CommonResponseObjDebugPayload
 */
export interface CommonResponseObjDebugPayload {
    /**
     * The minimum version of the function that can be called
     * @type {number}
     * @memberof CommonResponseObjDebugPayload
     */
    iVersionMin: number;
    /**
     * The maximum version of the function that can be called
     * @type {number}
     * @memberof CommonResponseObjDebugPayload
     */
    iVersionMax: number;
    /**
     * An array of permissions required to access this function.  If the value \"0\" is present in the array, anyone can call this function.  You must have one of the permission to access the function. You don\'t need to have all of them.
     * @type {Array<number>}
     * @memberof CommonResponseObjDebugPayload
     */
    a_RequiredPermissions: Array<number>;
}
