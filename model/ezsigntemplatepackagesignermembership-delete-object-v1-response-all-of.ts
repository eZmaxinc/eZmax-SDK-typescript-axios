/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.13
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackagesignermembershipDeleteObjectV1ResponseMPayload } from './ezsigntemplatepackagesignermembership-delete-object-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsigntemplatepackagesignermembershipDeleteObjectV1ResponseAllOf
 */
export interface EzsigntemplatepackagesignermembershipDeleteObjectV1ResponseAllOf {
    /**
     * 
     * @type {EzsigntemplatepackagesignermembershipDeleteObjectV1ResponseMPayload}
     * @memberof EzsigntemplatepackagesignermembershipDeleteObjectV1ResponseAllOf
     */
    'mPayload': EzsigntemplatepackagesignermembershipDeleteObjectV1ResponseMPayload;
}
/**
 * A EzsigntemplatepackagesignermembershipDeleteObjectV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatepackagesignermembershipDeleteObjectV1ResponseAllOf
 */
export class DefaultObjectEzsigntemplatepackagesignermembershipDeleteObjectV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsigntemplatepackagesignermembershipDeleteObjectV1ResponseMPayload> = {}
}


