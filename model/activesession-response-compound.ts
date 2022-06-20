/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.9
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { ActivesessionResponse } from './activesession-response';
import { ActivesessionResponseCompoundAllOf } from './activesession-response-compound-all-of';
import { ActivesessionResponseCompoundApikey } from './activesession-response-compound-apikey';
import { ActivesessionResponseCompoundUser } from './activesession-response-compound-user';
import { FieldEActivesessionUsertype } from './field-eactivesession-usertype';
import { FieldEActivesessionWeekdaystart } from './field-eactivesession-weekdaystart';

/**
 * @type ActivesessionResponseCompound
 * Payload for GET /1/object/activesession/getCurrent
 * @export
 */
export type ActivesessionResponseCompound = ActivesessionResponse & ActivesessionResponseCompoundAllOf;


