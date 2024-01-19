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
import { EzsigndiscussionResponseCompound } from './ezsigndiscussion-response-compound';

/**
 * Payload for GET /2/object/ezsigndiscussion/{pkiEzsigndiscussionID}
 * @export
 * @interface EzsigndiscussionGetObjectV2ResponseMPayload
 */
export interface EzsigndiscussionGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {EzsigndiscussionResponseCompound}
     * @memberof EzsigndiscussionGetObjectV2ResponseMPayload
     */
    'objEzsigndiscussion': EzsigndiscussionResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigndiscussionResponseCompound } from './'
// @ts-ignore
import { ValidationObjectEzsigndiscussionResponseCompound } from './'

/**
 * @export 
 * A EzsigndiscussionGetObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndiscussionGetObjectV2ResponseMPayload
 */
export class DataObjectEzsigndiscussionGetObjectV2ResponseMPayload {
   objEzsigndiscussion:EzsigndiscussionResponseCompound = new DataObjectEzsigndiscussionResponseCompound()
}

/**
 * @export 
 * A EzsigndiscussionGetObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectEzsigndiscussionGetObjectV2ResponseMPayload
 */
export class ValidationObjectEzsigndiscussionGetObjectV2ResponseMPayload {
   objEzsigndiscussion = new ValidationObjectEzsigndiscussionResponseCompound()
} 


