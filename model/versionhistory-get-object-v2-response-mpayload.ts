/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.14
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { VersionhistoryResponseCompound } from './versionhistory-response-compound';

import { DefaultObject } from '../base'

/**
 * Payload for GET /2/object/versionhistory/{pkiVersionhistoryID}
 * @export
 * @interface VersionhistoryGetObjectV2ResponseMPayload
 */
export interface VersionhistoryGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {VersionhistoryResponseCompound}
     * @memberof VersionhistoryGetObjectV2ResponseMPayload
     */
    'objVersionhistory': VersionhistoryResponseCompound;
}
/**
 * A VersionhistoryGetObjectV2ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectVersionhistoryGetObjectV2ResponseMPayload
 */
export class DefaultObjectVersionhistoryGetObjectV2ResponseMPayload extends DefaultObject {
   objVersionhistory:Partial<VersionhistoryResponseCompound> = {}
}


