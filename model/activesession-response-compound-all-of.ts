/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.4
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { ActivesessionResponseCompoundApikey } from './activesession-response-compound-apikey';
import { ActivesessionResponseCompoundUser } from './activesession-response-compound-user';

/**
 * 
 * @export
 * @interface ActivesessionResponseCompoundAllOf
 */
export interface ActivesessionResponseCompoundAllOf {
    /**
     * An array of permissions granted to the user or api key
     * @type {Array<number>}
     * @memberof ActivesessionResponseCompoundAllOf
     */
    'a_pkiPermissionID': Array<number>;
    /**
     * 
     * @type {ActivesessionResponseCompoundUser}
     * @memberof ActivesessionResponseCompoundAllOf
     */
    'objUserReal': ActivesessionResponseCompoundUser;
    /**
     * 
     * @type {ActivesessionResponseCompoundUser}
     * @memberof ActivesessionResponseCompoundAllOf
     */
    'objUserCloned'?: ActivesessionResponseCompoundUser;
    /**
     * 
     * @type {ActivesessionResponseCompoundApikey}
     * @memberof ActivesessionResponseCompoundAllOf
     */
    'objApikey'?: ActivesessionResponseCompoundApikey;
    /**
     * An Array of Registered modules.  These are the modules that are Licensed to be used by the User or the API Key.
     * @type {Array<string>}
     * @memberof ActivesessionResponseCompoundAllOf
     */
    'a_eModuleInternalname': Array<string>;
}
